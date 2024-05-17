use crate::JwtAlg;
use anyhow::Result;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

const JWT_SECRET: &[u8] = b"secret";

#[derive(Debug, Serialize, Deserialize)]
pub struct JwtClaims {
    pub aud: String,
    pub sub: String,
    pub exp: i64,
}

impl JwtClaims {
    pub fn new(aud: String, sub: String, exp: i64) -> Self {
        JwtClaims { aud, sub, exp }
    }
}

pub async fn jwt_encode(claims: &JwtClaims, alg: JwtAlg) -> Result<String> {
    let (header, key) = match alg {
        JwtAlg::HS256 => (
            Header::new(Algorithm::HS256),
            EncodingKey::from_secret(JWT_SECRET),
        ),
        JwtAlg::HS384 => unimplemented!(),
        JwtAlg::HS512 => unimplemented!(),
        JwtAlg::RS256 => unimplemented!(),
        JwtAlg::RS384 => unimplemented!(),
        JwtAlg::RS512 => unimplemented!(),
        JwtAlg::ES256 => unimplemented!(),
        JwtAlg::ES384 => unimplemented!(),
        JwtAlg::ES512 => unimplemented!(),
    };
    eprintln!("header={header:?}, claims={claims:?}");
    Ok(encode(&header, &claims, &key)?)
}

pub fn jwt_verify(token: &str, aud: &str, sub: &str) -> Result<bool> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_audience(&[aud.to_string()]);
    validation.sub = Some(sub.to_string());
    validation.set_required_spec_claims(&["exp", "aud", "sub"]);
    let data = decode::<JwtClaims>(token, &DecodingKey::from_secret(JWT_SECRET), &validation)?;
    eprintln!("header={:?}, claims={:?}", data.header, data.claims);
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_encode() {
        let claims = JwtClaims::new("aud".into(), "sub".into(), 1000);
        let token = jwt_encode(&claims, JwtAlg::HS256).unwrap();
        assert_eq!(jwt_verify(&token, "aud", "sub").unwrap(), true);
    }
}
