module FPE.FF1 (encrypt, decrypt, BlockCipher, Crypter, Tweak) where

import Data.Bits
import Control.Arrow
import Control.Monad
import Data.Tuple (swap)
import Math.NumberTheory.Logarithms
import Data.Vector.Generic (Vector)
import qualified Data.Vector.Generic as V
import qualified Data.ByteString as S
import qualified Data.ByteString.Lazy as L

type BlockCipher = S.ByteString -> S.ByteString
type Tweak = S.ByteString
type Crypter v a = BlockCipher -> Int -> Tweak -> v a -> v a


--  Number of bytes to store a message of given length and radix.
--  Defined in FF1 step 3 using (redundant) double ceiling.
bytesFor :: Int -> Int -> Int
bytesFor radix len =
   integerLog2 ((fromIntegral radix ^ len) - 1) `div` 8 + 1

xorBytes :: S.ByteString -> S.ByteString -> S.ByteString
xorBytes a b = S.pack $ S.zipWith xor a b

--  Conversion functions.

vecToNum :: (Vector v a, Integral a) => Int -> v a -> Integer
vecToNum radix = V.foldl go 0 where
   go val c = val * fromIntegral radix + fromIntegral c

numToVec :: (Vector v a, Integral a) => Int -> Int -> Integer -> v a
numToVec radix len num = V.reverse $ V.fromListN len $
   map (fromIntegral . (`mod` radix_)) $ iterate (`div` radix_) num
      where radix_ = fromIntegral radix

--  Same as above, but with a ByteString of fixed radix.
--  Possibly we could use Vector Word8 instead of ByteStrings?

bytesToNum :: Integral a => S.ByteString -> a
bytesToNum = S.foldl (\val c -> val * 256 + fromIntegral c) 0
{-# SPECIALIZE bytesToNum :: S.ByteString -> Integer #-}

numToBytes :: Integral a => Int -> a -> S.ByteString
numToBytes len num = S.reverse $ S.pack $ map fromIntegral $
   take len $ iterate (`div` 256) num

--  Cipherish functions.

prf :: BlockCipher -> S.ByteString -> S.ByteString
prf cipher = loop (S.replicate 16 0) where
   loop y src = if S.null rest then y' else loop y' rest where
      (x, rest) = S.splitAt 16 src
      y' = cipher $ x `xorBytes` y

--  Extends (or shortens) a block to arbitrary length using secure hashing.
extend :: BlockCipher -> Int -> S.ByteString -> S.ByteString
extend cipher len blk = L.toStrict $ L.take (fromIntegral len) $ L.fromChunks $
   blk : [ cipher $ blk `xorBytes` numToBytes @Int 16 i | i <- [1..] ]


--  Encrypt and decrypt.

--  True for encryption, False for decryption.
crypt :: (Vector v a, Integral a) => Bool -> Crypter v a
crypt isEncrypt cipher radix tweak msg =
   numToVec radix u finalA V.++ numToVec radix v finalB where
      t = S.length tweak
      n = V.length msg; u = n `div` 2; v = n - u
      b = bytesFor radix v
      d = 4*((b-1)`div`4) + 8
      rpow = (fromIntegral radix ^)
      bP = S.concat [
            S.pack [1, 2, 1], numToBytes 3 radix,
            S.pack [10, fromIntegral u], numToBytes 4 n, numToBytes 4 t]
      pfxQ = tweak <> S.pack (replicate ((-t-b-1)`mod`16) 0)
      (numA0, numB0) = join (***) (vecToNum radix) $ V.splitAt u msg
      loop (numA, numB) i = (numB, numC) where
         y = bytesToNum $ extend cipher d $ prf cipher $ S.concat [
               bP, pfxQ, S.singleton i, numToBytes b numB]
         op = if isEncrypt then (+ y) else subtract y
         numC = op numA `mod` (if even i then rpow u else rpow v)
      wrap = if isEncrypt then id else swap
      (finalA, finalB) = wrap $
         foldl loop (wrap (numA0, numB0)) $
         if isEncrypt then [0..9] else [9,8..0]

encrypt, decrypt :: (Vector v a, Integral a) => Crypter v a
encrypt = crypt True
decrypt = crypt False

