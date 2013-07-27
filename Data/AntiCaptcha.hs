{-# LANGUAGE OverloadedStrings #-}
module Data.AntiCaptcha
    ( AntiCaptchaConfig (..)
    , AntiCaptcha
    , antiCaptchaFromConfig
    , antiCaptchaFromComponents
    , antiCaptchaFromConfigWithSpinner
    , antiCaptchaSpinner
    , antiCaptchaHash
    ) where

import Prelude
import Crypto.Hash
import Data.Text (Text)

import qualified Data.ByteString.UTF8 as BS8
import qualified Data.Text as T
import qualified Data.Text.Lazy as TL
import qualified Data.Text.Encoding as TE

data AntiCaptchaConfig digest = AntiCaptchaConfig 
    { accHashFunc :: (BS8.ByteString -> Digest digest)
    , accEntry :: T.Text
    , accClientIpAddress :: T.Text
    , accSecondsEpoch :: Integer
    , accSalt :: T.Text
    , accSecret :: T.Text
    }
                                           
data AntiCaptcha = AntiCaptcha
    { acHashFunc :: T.Text -> T.Text
    , acSpinner :: T.Text
    , acSalt :: T.Text
    , acSecret :: T.Text
    }
    
instance Eq AntiCaptcha where
    (==) ac oac = let
            spinner = (acSpinner ac) == (acSpinner oac)
            salt = (acSalt ac) == (acSalt oac)
            secret = (acSecret ac) == (acSecret oac)
            hashFunc = (antiCaptchaHash ac "") == (antiCaptchaHash oac "")
        in if spinner && salt && secret
            then hashFunc
            else False
                

antiCaptchaFromConfig :: AntiCaptchaConfig a -> AntiCaptcha
antiCaptchaFromConfig acc = let hashFunc = antiCaptchaHashFunc (accHashFunc acc)
                                salt = accSalt acc
                                secret = hashFunc $ accSecret acc
                                secondsEpoch = T.pack . show . accSecondsEpoch $ acc
                                list = [accEntry acc, secondsEpoch, accClientIpAddress acc, secret]
                                spinner = hashFunc . TL.toStrict . (TL.intercalate ":") $ map TL.fromStrict list
                            in AntiCaptcha hashFunc spinner salt secret

antiCaptchaFromComponents :: (BS8.ByteString -> Digest a) -> Text -> Text -> Text -> AntiCaptcha
antiCaptchaFromComponents hashFunc salt secret spinner = let hf = antiCaptchaHashFunc hashFunc
                                                             scrt = hf secret
                                                         in AntiCaptcha hf spinner salt scrt
                                                         
antiCaptchaFromConfigWithSpinner :: AntiCaptchaConfig a -> Text -> AntiCaptcha
antiCaptchaFromConfigWithSpinner config spinner = antiCaptchaFromComponents (accHashFunc config) (accSalt config) (accSecret config) spinner
                                                         
antiCaptchaSpinner :: AntiCaptcha -> Text
antiCaptchaSpinner = acSpinner

antiCaptchaHash :: AntiCaptcha -> T.Text -> T.Text
antiCaptchaHash ac value = let hashFunc = acHashFunc ac
                               salt = TL.fromStrict $ acSalt ac
                               spinner = acSpinner ac
                               secret = acSecret ac
                               acString = TL.intercalate salt $ map TL.fromStrict [value, spinner, secret]
                           in hashFunc . TL.toStrict $ acString
                           
antiCaptchaHashFunc :: (BS8.ByteString -> Digest a) -> T.Text -> T.Text
antiCaptchaHashFunc hashFunc = TE.decodeUtf8 . digestToHexByteString . hashFunc . TE.encodeUtf8