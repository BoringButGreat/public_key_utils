# PublicKeyUtils

Some basic functions for working with erlang's public_key module.

##### Current Features
* Parsing Keys
  * EC, RSA, and DSA Algorithms
  * SSL PEM and DER formats for both public and private keys
  * OpenSSH public and private key formats
* Parsing x509 Certificates
  * SSL PEM and DER formats
  * Extracts much of the metadata encoded in the certificate
* Digital Signatures
  * ECDSA, RSA, DSA Algorithms
* Encryption and Decryption
  * RSA only

##### Known Issues
* Explicit EC Curve parameter declarations will not work, only named curves referenced by oid.

##### Examples
```elixir
alias PublicKeyUtils.{Key, Certificate}

{:ok, key} = Key.load(File.read!("some.key")) # id_rsa, key.pem, etc.
signature =
  File.read!("source")
  |> Key.sign(key, :sha512) # or blank for :sha

{:ok, public_key} = Key.public(key) # or read it from a file, or paste in ssh-rsa XXXX from authorized_keys

File.read!("source")
|> Key.verify(signature, public_key, :sha512)
|> if do
     IO.puts "Signed data!"
   else
     IO.puts "Signature invalid"
   end

# Typically RSA encryption is coupled with symmetric key encryption and signatures.
# This is just raw RSA encryption
# You can do your own double-key encryption (sender's private, receiver's public)
encrypted =
  File.read!("source")
  |> Key.encrypt(public_key)

{:ok, decrypted} = Key.decrypt(encrypted, key)

{:ok, certificates} = Certificate.load("file")
all_fingerprints = Enum.flat_map(certificates, &(&1.fingerprints))
```

### Why?

Just calling :public_key functions works really well, when you control the data coming in.
In fact, you should not add another dep to your app if you are in control of the keys and certificates, just use `:public_key.decode_pem` or `:public_key.der_decode(:RSAPrivateKey, File.read!("keyfile"))`.
This library was created for the cases where you expect to deal with a variety of different formats and compatibility is more desirable than adding a dependency is undesirable.

My motivation for creating this is mainly to work with SAML, where users self-configure their integration by using metadata.xml or manually using public keys and certificates they upload.
However, I also think this is a good way to work with user uploaded keys of other kinds (ssh keys, self-signed cert authentication, etc.).

Currently tested against:
* OpenSSL (ec, rsa, dsa, self-signed)
* OpenSSH (private, public, ec, rsa, dsa)

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed as:

  1. Add `public_key_utils` to your list of dependencies in `mix.exs`:

    ```elixir
    def deps do
      [{:public_key_utils, "~> 0.1.0"}]
    end
    ```

  2. Ensure `public_key_utils` is started before your application:

    ```elixir
    def application do
      [applications: [:public_key_utils]]
    end
    ```
