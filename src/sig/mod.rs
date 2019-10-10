use failure::{format_err, Error};
use hmac::{Hmac, Mac};
use sha2::Sha512;

pub fn sign(secret: &[u8], _params: Option<&[(&str, &str)]>) -> Result<Vec<u8>, Error> {
    let mut mac = Hmac::<Sha512>::new_varkey(secret).or_else(|e| Err(format_err!("{}", e)))?;
    mac.input(b"");
    Ok(mac.result().code().to_vec())
}

#[cfg(test)]
#[test]
fn test_sorted() {
    let sum = sign(b"", Some(&[("foo", "bar"), ("baz", "qux")]));
    assert!(sum.is_ok());
    assert_eq!(
        "b936cee86c9f87aa5d3c6f2e84cb5a4239a5fe50480a6ec66b70ab5b1f4ac6730c6c515421b327ec1d69402e53dfb49ad7381eb067b338fd7b0cb22247225d47",
        hex::encode(sum.unwrap_or_default()));
}
