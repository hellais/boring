/*
Should be compiled with the pq-experimental flag turned on:

cargo run --features pq-experimental --example parrot
*/
use boring::ssl::{
    CertificateCompressionAlgorithm, CertificateCompressor, SslConnector, SslCurve, SslMethod,
    SslOptions, SslSignatureAlgorithm, SslVersion,
};
use std::io::Write;
use std::net::ToSocketAddrs;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

struct BrotliCompressor {
    q: u32,
    lgwin: u32,
}

impl Default for BrotliCompressor {
    fn default() -> Self {
        Self { q: 11, lgwin: 32 }
    }
}

impl CertificateCompressor for BrotliCompressor {
    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::BROTLI
    }

    fn can_compress(&self) -> bool {
        true
    }

    fn can_decompress(&self) -> bool {
        true
    }

    fn compress<W>(&self, input: &[u8], output: &mut W) -> std::io::Result<()>
    where
        W: std::io::Write,
    {
        let mut writer = brotli::CompressorWriter::new(output, 1024, self.q, self.lgwin);
        writer.write_all(&input)?;
        Ok(())
    }

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> std::io::Result<()>
    where
        W: std::io::Write,
    {
        brotli::BrotliDecompress(&mut std::io::Cursor::new(input), output)?;
        Ok(())
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Compare against https://tls.peet.ws/api/all
    let addr = "tls.peet.ws:443".to_socket_addrs().unwrap().next().unwrap();
    let stream = TcpStream::connect(&addr).await.unwrap();

    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.clear_options(
        SslOptions::NO_SSLV2 | SslOptions::NO_SSLV3 | SslOptions::NO_TLSV1 | SslOptions::NO_TLSV1_1,
    );
    connector.set_cipher_list("ALL:!aPSK:!ECDSA+SHA1:!3DES")?;
    connector.set_grease_enabled(true);
    connector.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    connector.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    connector.enable_signed_cert_timestamps();
    connector.set_alpn_protos(b"\x02h2\x08http/1.1")?;
    connector.enable_ocsp_stapling();
    connector.add_certificate_compression_algorithm(BrotliCompressor::default())?;

    connector.set_verify_algorithm_prefs(&[
        SslSignatureAlgorithm::ECDSA_SECP256R1_SHA256,
        SslSignatureAlgorithm::RSA_PSS_RSAE_SHA256,
        SslSignatureAlgorithm::RSA_PKCS1_SHA256,
        SslSignatureAlgorithm::ECDSA_SECP384R1_SHA384,
        SslSignatureAlgorithm::RSA_PSS_RSAE_SHA384,
        SslSignatureAlgorithm::RSA_PKCS1_SHA384,
        SslSignatureAlgorithm::RSA_PSS_RSAE_SHA512,
        SslSignatureAlgorithm::RSA_PKCS1_SHA512,
    ])?;

    connector.set_curves(&[
        SslCurve::X25519_MLKEM768,
        SslCurve::X25519,
        SslCurve::SECP256R1,
        SslCurve::SECP384R1,
    ])?;

    let mut config = connector.build().configure().unwrap();
    config.add_application_settings(b"h2", b"")?;
    config.enable_ech_grease()?;

    let mut stream = tokio_boring::connect(config, "tls.peet.ws", stream)
        .await
        .unwrap();

    stream
        .write_all(b"GET /api/all HTTP/1.0\r\n\r\n")
        .await
        .unwrap();

    let mut buf = vec![];
    stream.read_to_end(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf);
    let response = response.trim_end();
    println!("{}", response);
    Ok(())
}
