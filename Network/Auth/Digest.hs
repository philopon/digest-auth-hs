{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE ExistentialQuantification #-}

module Network.Auth.Digest
    ( User, Password, Method
    -- * configuration
    , HasRealm
    , DigestAuthConfig
    , digestAuthRealm
    , digestAuthNonceLength
    , digestAuthNonceExpire
    , digestAuthCryptoPassword

    -- * DigestAuth
    -- ** state
    , DigestAuth
    , createDigestAuth, createSystemDigestAuth
    -- * 
    , EncryptedPassword(..)
    , encryptoPassword
    , wwwAuthenticate
    , checkAuth
    ) where

import Control.Monad
import Control.Monad.IO.Class
import Control.Applicative
import Control.Concurrent

import qualified Data.ByteString as S
import qualified Data.ByteString.Lex.Integral as S
import qualified Data.ByteString.Char8 as S8
import qualified Data.ByteString.Base64 as S
import qualified Data.Attoparsec.ByteString.Char8 as A

import "crypto-random" Crypto.Random
import Crypto.Hash
import Crypto.Random.AESCtr

import Control.Monad.STM
import qualified STMContainers.Map as STMMap
import qualified STMContainers.Set as STMSet
import Data.IORef
import Data.String(IsString(..))

import qualified Focus

type User = S.ByteString
type Password = S.ByteString
type Method = S.ByteString

data DigestAuthConfig m = DigestAuthConfig
    { digestAuthRealm          :: S.ByteString
    , digestAuthNonceLength    :: Int
    , digestAuthNonceExpire    :: (Maybe Int) -- ^ nonce expire time(ms).
    , digestAuthCryptoPassword :: User -> m (Maybe EncryptedPassword) -- ^ username to encrepted password function.
    }

defaultDigestAuthConfig :: Monad m => DigestAuthConfig m
defaultDigestAuthConfig = DigestAuthConfig "" 30 (Just (60*10^(6::Int))) (const $ return Nothing)

instance Monad m => IsString (DigestAuthConfig m) where
    fromString s = defaultDigestAuthConfig { digestAuthRealm = S8.pack s }

data DigestAuth m = forall rng. CPRG rng => DigestAuth
    (DigestAuthConfig m) (IORef rng) (STMMap.Map S.ByteString (STMSet.Set Int))

digestAuthConfig :: DigestAuth m -> DigestAuthConfig m
digestAuthConfig (DigestAuth c _ _) = c
{-# INLINE digestAuthConfig #-}

class HasRealm a where
    getRealm :: a -> S.ByteString

instance HasRealm (DigestAuthConfig m) where
    getRealm = digestAuthRealm
    {-# INLINE getRealm #-}

instance HasRealm (DigestAuth m) where
    getRealm = digestAuthRealm . digestAuthConfig
    {-# INLINE getRealm #-}

instance HasRealm S.ByteString where
    getRealm = id
    {-# INLINE getRealm #-}

-- | create DigestAuth state from CPRG.
createDigestAuth :: CPRG rng => DigestAuthConfig m -> rng -> IO (DigestAuth m)
createDigestAuth cfg rng = do
    m   <- STMMap.newIO
    ref <- newIORef rng
    return $ DigestAuth cfg ref m

-- | create DigestAuth state from System 'AESRNG'.
createSystemDigestAuth :: DigestAuthConfig m -> IO (DigestAuth m)
createSystemDigestAuth cfg = makeSystem >>= createDigestAuth cfg

md5Hex :: S.ByteString -> S.ByteString
md5Hex s = digestToHexByteString (hash s :: Digest MD5)
{-# INLINE md5Hex #-}

newtype EncryptedPassword = EncryptedPassword S.ByteString

-- | make encrypted password. you should store to db encrypted password(not raw password).
encryptoPassword :: HasRealm a => a -> User -> Password -> EncryptedPassword
encryptoPassword cfg user pass = EncryptedPassword . md5Hex $
    S.intercalate ":" [user, getRealm cfg, pass]

swap :: (a,b) -> (b,a)
swap (a,b) = (b,a)
{-# INLINE swap #-}

wwwAuthenticate' :: Bool -> DigestAuth m -> IO S.ByteString
wwwAuthenticate' stale (DigestAuth cfg rng store) = do
    nonce <- fmap S.encode $ atomicModifyIORef' rng $
        swap . cprgGenerate (digestAuthNonceLength cfg)
    atomically $ STMSet.new >>= \s -> STMMap.insert s nonce store
    case digestAuthNonceExpire cfg of
        Nothing -> return ()
        Just xp -> void . forkIO $ do
            threadDelay xp
            atomically $ STMMap.delete nonce store
    return . S.concat $
        [ "Digest realm=\"", digestAuthRealm cfg
        , "\",algorithm=MD5,qop=\"auth\",nonce=\"", nonce
        , "\",stale=", if stale then "true" else "false"
        ]

-- | create \"WWW-Authenticate\" header value.
-- 
-- you should return response 401 with this header to client.
wwwAuthenticate :: DigestAuth m -> IO S.ByteString
wwwAuthenticate = wwwAuthenticate' False

authorizationP :: A.Parser [(S.ByteString, S.ByteString)]
authorizationP = A.string "Digest" *> A.skipSpace *> A.sepBy pair (A.char ',' *> A.skipSpace)
  where
    pair   = (,) <$> key <*> (A.char '=' *> (qValue <|> value))
    key    = A.takeWhile1 (/= '=')
    value  = A.takeWhile1 (`notElem` " ,")
    qValue = (A.char '"' *> A.takeWhile1 (/= '"') <* A.char '"') <* A.skipSpace

type URI    = S.ByteString
type Nonce  = S.ByteString
type NC     = S.ByteString
type CNonce = S.ByteString
type QOP    = S.ByteString
calcResponse :: EncryptedPassword -> Method -> URI -> Nonce -> NC -> CNonce -> QOP -> S.ByteString
calcResponse (EncryptedPassword a1) method uri nonce nc cnonce qop =
    let a2 = md5Hex $ S.intercalate ":" [method, uri]
    in md5Hex $ S.intercalate ":" [a1, nonce, nc, cnonce, qop, a2]

-- | check authenticated.
--
-- * Nothing: auth successed.
-- * Just h: auth failed. you should return response 401 with \"WWW-Authenticate: h\" header.
checkAuth :: (MonadIO m, MonadPlus m) => DigestAuth m -> Method -> S.ByteString -> m (Maybe S.ByteString)
checkAuth digest@(DigestAuth cfg _ store) method hdr = case A.parseOnly authorizationP hdr of
    Left _     -> liftIO $ Just <$> wwwAuthenticate digest
    Right auth -> do
        resp     <- maybe mzero return $ lookup "response" auth
        user     <- maybe mzero return $ lookup "username" auth
        cnonce   <- maybe mzero return $ lookup "cnonce" auth
        nonce    <- maybe mzero return $ lookup "nonce" auth
        uri      <- maybe mzero return $ lookup "uri" auth
        qop      <- maybe mzero return $ lookup "qop" auth
        (nc,nci) <- maybe mzero (\s -> case S.readHexadecimal s of
            Just (r, "") -> return (s,r)
            _            -> mzero) $ lookup "nc" auth
        ncState  <- liftIO . atomically $ STMMap.focus (checkNc nci) nonce store
        crypto   <- digestAuthCryptoPassword cfg user
        case ncState of
            True  -> liftIO $ Just <$> wwwAuthenticate' True digest
            False -> case crypto of
                Nothing -> liftIO $ Just <$> wwwAuthenticate digest
                Just cp -> do
                    let resp' = calcResponse cp method uri nonce nc cnonce qop
                    if resp == resp'
                        then return Nothing
                        else liftIO $ Just <$> wwwAuthenticate digest
  where
    checkNc _  Nothing  = return (True, Focus.Keep)
    checkNc nc (Just s) = STMSet.lookup nc s >>= \case
        False -> STMSet.insert nc s >> return (False, Focus.Keep)
        True  -> return (True, Focus.Remove)
