import FPE.FF1 as FF1
import Crypto.Cipher.Types
import Crypto.Cipher.AES
import Crypto.Error
import Control.Monad (when)

import qualified Data.Vector.Unboxed as V
import qualified Data.ByteString as B


--  The first two samples from
--  https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/FF1samples.pdf

CryptoPassed (key :: AES128) = cipherInit $ B.pack [
  0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
  0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]

main = do
   let cipher = ecbEncrypt key
   let tweak = mempty
   let plain = V.fromList @Int [0..9]
   let crypt = FF1.encrypt cipher 10 tweak plain
   print crypt
   when (V.toList crypt /= [2,4,3,3,4,7,7,4,8,4]) $ error "bad encrypt"
   when (FF1.decrypt cipher 10 tweak crypt /= plain) $ error "bad decrypt"
   let tweak = B.pack [ 0x39, 0x38 .. 0x30]
   let crypt = FF1.encrypt cipher 10 tweak plain
   print crypt
   when (V.toList crypt /= [6,1,2,4,2,0,0,7,7,3]) $ error "bad tweak encrypt"

