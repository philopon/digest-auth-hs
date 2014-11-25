{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

import Network.Auth.Digest
import Network.Wai
import Network.Wai.Handler.Warp
import Network.HTTP.Types

import qualified Data.ByteString.Char8 as S8

main :: IO ()
main = do
    let cfg = "Digest Auth" :: DigestAuthConfig IO
        cry = encryptoPassword cfg "test" "test"
        cfg' = cfg { digestAuthCryptoPassword = \case
            "test" -> return $ Just cry
            _      -> return $ Nothing
            }
    digest <- createSystemDigestAuth (cfg' :: DigestAuthConfig IO)
    putStrLn "access http://localhost:3000 and login as test:test."
    run 3000 (app digest)

app :: DigestAuth IO -> Application
app digest req send = do
    case lookup "Authorization" (requestHeaders req) of
        Nothing   -> do
            auth  <- wwwAuthenticate digest
            send $ responseLBS status401 [("WWW-Authenticate", auth)] ""
        Just auth -> S8.putStrLn auth >> checkAuth digest (requestMethod req) auth >>= \case
            Nothing  -> send $ responseLBS status200 [] "Ok"
            Just hdr -> send $ responseLBS status401 [("WWW-Authenticate", hdr)] ""
