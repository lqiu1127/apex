<?php

// Symmetric Encryption

// Cipher method to use for symmetric encryption
const CIPHER_METHOD = 'AES-256-CBC';

function key_encrypt($string, $key, $cipher_method=CIPHER_METHOD) {
    $key = str_pad($key, 32, '*'); //get the keys entered
    $iv_length = openssl_cipher_iv_length(CIPHER_METHOD);
    //random initialization vector 
    $iv = openssl_random_pseudo_bytes($iv_length);
    //encrypt
    $encrypted = openssl_encrypt($string, CIPHER_METHOD, $key, OPENSSL_RAW_DATA, $iv);
    $message = $iv . $encrypted;
    return base64_encode($message);
}

function key_decrypt($string, $key, $cipher_method=CIPHER_METHOD) {
    $key = str_pad($key, 32, '*');
    $iv_with_ciphertext = base64_decode($string);
    $iv_length = openssl_cipher_iv_length(CIPHER_METHOD);
    //get initialization vector 
    $iv = substr($iv_with_ciphertext, 0, $iv_length);
    //get cipher
    $ciphertext = substr($iv_with_ciphertext, $iv_length);
    //decrypt with cipher and iv  
    $plaintext = openssl_decrypt($ciphertext, CIPHER_METHOD, $key, OPENSSL_RAW_DATA, $iv);
    return $plaintext;
}


// Asymmetric Encryption / Public-Key Cryptography

// Cipher configuration to use for asymmetric encryption
const PUBLIC_KEY_CONFIG = array(
    "digest_alg" => "sha512",
    "private_key_bits" => 2048,
    "private_key_type" => OPENSSL_KEYTYPE_RSA,
);
/*
function generate_keys($config=PUBLIC_KEY_CONFIG) {
  
  $resource = openssl_pkey_new($config);

  //generate public key  
  //$key_details = openssl_pkey_get_details($resource);
  //$public_key = $key_details['key'];
  $public_key = openssl_pkey_get_public($resource);
  $private_key = openssl_pkey_get_private($resource);
  
  //checks for error, not compatable with windows
  //echo openssl_error_string();

  return array('private' => $private_key, 'public' => $public_key);

}
*/
function generate_keys($config=PUBLIC_KEY_CONFIG) {
  
  $resource = openssl_pkey_new($config);
  
  // Extract private key from the pair
  openssl_pkey_export($resource, $private_key);
  
  // Extract public key from the pair
  $key_details = openssl_pkey_get_details($resource);
  $public_key = $key_details["key"];
  return array('private' => $private_key, 'public' => $public_key);
}

function pkey_encrypt($string, $public_key) {
  openssl_public_encrypt($string, $encrypted, $public_key);
  return base64_encode($encrypted);
}
function pkey_decrypt($string, $private_key) {
  openssl_private_decrypt(base64_decode($string), $decrypted, $private_key);
  return $decrypted;
}
// Digital signatures using public/private keys
function create_signature($data, $private_key) {
  openssl_sign($data, $raw_signature, $private_key);
  $signature = base64_encode($raw_signature);
  return $signature;
}
function verify_signature($data, $signature, $public_key) {
  // Vigenère
  $result = openssl_verify($data, base64_decode($signature), $public_key);
  return $result;
}

?>
