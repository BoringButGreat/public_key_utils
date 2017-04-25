import Record
import PublicKeyUtils.OID
import :crypto, only: [hash: 2]

defmodule PublicKeyUtils.Certificate do
  defstruct [
    :version,
    :certificate,
    :serial_number,
    :issuer,
    :validity,
    :subject,
    :subject_public_key_info,
    :issuer_unique_id,
    :subject_unique_id,
    :extensions,
    :signature_algorithm,
    :signature,
    :fingerprints
  ]

  hrl = [from_lib: "public_key/include/public_key.hrl"]
  defrecord :certificate, :Certificate, extract(:Certificate, hrl)
  defrecord :tbs_certificate, :TBSCertificate, extract(:TBSCertificate, hrl)

  @doc """
  Returns any certificates found

  Parameters
  - `certificates` - One or more certificates in PEM or DER or Erlang :public_key format
  """
  def load(certificates), do: _load_certificates(certificates, [])
  defp _load_certificates([], []), do: {:error, :no_certificates}
  defp _load_certificates([], found), do: {:ok, List.flatten(found)}
  defp _load_certificates([certificate | rest], found) do
    case _load_certificates(certificate, found) do
      {:ok, certificates} -> _load_certificates(rest, [found, certificates])
      _ ->_load_certificates(rest, found)
    end
  end
  defp _load_certificates({:Certificate, der, :not_encrypted}, certs) do
    found =
      try do
        case :public_key.der_decode(:Certificate, der) do
          certificate(
            tbsCertificate: tbs_certificate(
              version: version,
              serialNumber: serial_number,
              issuer: issuer,
              validity: validity,
              subject: subject,
              subjectPublicKeyInfo: subject_public_key_info,
              issuerUniqueID: issuer_unique_id,
              subjectUniqueID: subject_unique_id,
              extensions: extensions
            ),
            signatureAlgorithm: signature_algorithm,
            signature: signature
          ) = cert ->
            [
              certs,
              %__MODULE__{
                version: version,
                certificate: cert,
                serial_number: serial_number,
                issuer: decode(issuer),
                validity: decode(validity),
                subject: decode(subject),
                subject_public_key_info: decode(subject_public_key_info),
                issuer_unique_id: decode(issuer_unique_id),
                subject_unique_id: decode(subject_unique_id),
                extensions: decode(extensions),
                signature_algorithm: decode(signature_algorithm),
                signature: signature,
                fingerprints: fingerprint(der)
              }
            ]
          _ -> certs
        end
      catch
        _ -> certs
      end
    _load_certificates([], found)
  end
  defp _load_certificates(bin, certs) when is_binary(bin) do
    case :public_key.pem_decode(bin) do
      [] ->
        case Base.decode64(bin, ignore: :whitespace) do
          {:ok, bin} -> _load_certificates({:Certificate, bin, :not_encrypted}, certs)
          _ -> _load_certificates({:Certificate, bin, :not_encrypted}, certs)
        end
      entries -> _load_certificates(entries, certs)
    end
  end

  def der(%__MODULE__{certificate: cert}) do
    {:ok, :public_key.der_encode(:Certificate, cert)}
  end

  def pem(list) when is_list(list) do
    {:ok,
      Enum.map(list, fn(cert) ->
        :public_key.pem_entry_encode(:Certificate, cert.certificate)
      end)
      |> :public_key.pem_encode
    }
  end
  def pem(%__MODULE__{} = cert), do: pem([cert])

  defp fingerprint(der) do
    for alg <- [:sha, :sha256, :sha512], do: {alg, hash(alg, der)}
  end

  defp decode(nil), do: nil
  defp decode(<<len, str :: binary>>) when byte_size(str) == len, do: str
  defp decode(bin) when is_binary(bin) do
    case :asn1rt_nif.decode_ber_tlv(bin) do
      {{6, oid}, _} -> from_oid(oid)
      {{19, str}, _} -> str
      {{12, str}, _} -> str
      _ -> String.trim(bin)
    end
  end
  defp decode({:SubjectPublicKeyInfo, _, _} = key) do
    case PublicKeyUtils.Key.load(key) do
      {:ok, key} -> key
    end
  end
  defp decode({:AttributeTypeAndValue, oid, value}), do: {from_oid(oid), decode(value)}
  defp decode({:AlgorithmIdentifier, oid, _}), do: from_oid(oid)
  defp decode({:Extension, oid, _, raw}), do: {from_oid(oid), raw}
  defp decode({:rdnSequence, list}), do: List.flatten(decode(list))
  defp decode({:Validity, from, to}), do: [not_before: decode(from), not_on_or_after: decode(to)]
  defp decode(list) when is_list(list), do: Enum.map(list, &decode/1)
  defp decode({:utcTime, time}) do
    parse_time(time)
  end
  defp decode(oid), do: from_oid(oid)

  defp parse_time([y1,y2,mo1,mo2,d1,d2,h1,h2,m1,m2,s1,s2,tz] = time) do
    isoish = <<?2,?0,y1,y2,?-,mo1,mo2,?-,d1,d2,?T,h1,h2,?:,m1,m2,?:,s1,s2,tz>>
    case NaiveDateTime.from_iso8601(isoish) do
      {:ok, time} -> time
      _ -> {:unknown, to_string(time)}
    end
  end
  defp parse_time(time), do: {:unknown, to_string(time)}
end
