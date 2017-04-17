defmodule PublicKeyUtilsTest do
  use ExUnit.Case
  doctest PublicKeyUtils
  alias PublicKeyUtils.{Key, Certificate}
  import Macro, only: [escape: 1]

  for {id, data} <- TestData.data do
    describe id do
      if data["key"] do

        @tag data["key"].tags
        @tag private_key: true, key: true, loading: true
        test "private key loading" do
          {:ok, key} = Key.load(unquote(escape data["key"].file))
          assert key.private
          assert key.key
          assert key.algorithm
        end

        @tag data["key"].tags
        @tag private_key: true, key: true, signing: true, verifying: true
        test "signing and verifying" do
          {:ok, key} = Key.load(unquote(escape data["key"].file))
          pub = Key.public(key)

          signature = Key.sign("data", key)
          assert Key.verify("data", signature, key)
          assert Key.verify("data", signature, pub)
          refute Key.verify("baddata", signature, key)
          refute Key.verify("data", "bad" <> String.slice(signature, 3..-1), key)
        end

        if {:encryption, true} in data["key"].tags do
          @tag data["key"].tags
          @tag private_key: true, key: true, encryption: true, decryption: true
          test "encryption and decryption" do
            {:ok, key} = Key.load(unquote(escape data["key"].file))
            public = Key.public(key)

            encrypted = Key.encrypt("data", key)
            assert {:ok, "data"} == Key.decrypt(encrypted, public)
            encrypted = Key.encrypt("data", public)
            assert {:ok, "data"} == Key.decrypt(encrypted, key)
            assert {:error, :decrypt_failed} == Key.decrypt(encrypted, public)

            encrypted = Key.encrypt("data", public)
            assert {:ok, "data"} == Key.decrypt(encrypted, key)
            encrypted = Key.encrypt("data", key)
            assert {:ok, "data"} == Key.decrypt(encrypted, public)
          end
        end

        if data["pub"] do

          @tag data["key"].tags
          test "private to public matches public key" do
            {:ok, key} = Key.load(unquote(escape data["key"].file))
            {:ok, pub} = Key.load(unquote(escape data["pub"].file))
            assert Key.public(key) == pub
          end

        end
      end
      if data["pub"] do

        @tag data["pub"].tags
        @tag public_key: true, key: true, loading: true
        test "public key loading" do
          {:ok, key} = Key.load(unquote(escape data["pub"].file))
          refute key.private
          assert key.key
          assert key.algorithm
        end

      end
      if data["crt"] do

        @tag data["crt"].tags
        @tag certificate: true, loading: true
        test "certificate loading" do
          {:ok, [certificate]} = Certificate.load(unquote(escape data["crt"].file))
          assert certificate.fingerprints[:sha]
          assert certificate.issuer[:"id-at-organizationName"] == "ACME, Inc."
          assert certificate.issuer[:"id-at-localityName"] == "Coyote Springs"
          assert certificate.issuer[:"id-at-stateOrProvinceName"] == "Nevada"
          assert certificate.issuer[:"id-at-countryName"] == "US"
          assert certificate.subject[:"id-at-organizationName"] == "ACME, Inc."
          assert certificate.subject[:"id-at-localityName"] == "Coyote Springs"
          assert certificate.subject[:"id-at-stateOrProvinceName"] == "Nevada"
          assert certificate.subject[:"id-at-countryName"] == "US"
        end

        if data["pub"] do

          @tag data["pub"].tags
          test "certificate public key matches" do
            {:ok, [certificate]} = Certificate.load(unquote(escape data["crt"].file))
            {:ok, pkey} = Key.load(unquote(escape data["pub"].file))
            assert certificate.subject_public_key_info == pkey
          end

        end
      end
    end
  end
end
