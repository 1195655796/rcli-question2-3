use crate::{jwt_encode, jwt_verify, CmdExector, JwtClaims};
use clap::Parser;
use enum_dispatch::enum_dispatch;
use std::str::FromStr;
use time::{Duration, OffsetDateTime};

#[derive(Debug, Parser)]
#[enum_dispatch(CmdExector)]
pub enum JwtSubCommand {
    #[command(name = "sign", about = "sign JWT")]
    Encode(JwtEncodeOpts),
    #[command(name = "verify", about = "Verify JWT")]
    Verify(JwtVerifyOpts),
}

#[derive(Debug, Parser)]
pub struct JwtEncodeOpts {
    #[arg(long)]
    pub aud: String,
    #[arg(long)]
    pub sub: String,

    #[arg(long, default_value = "1d", value_parser = parse_offset_date_time)]
    pub exp: OffsetDateTime,

    #[arg(long, value_parser = parse_jwt_args, default_value = "HS256")]
    pub alg: JwtAlg,

    #[arg(long)]
    pub encode_secret: bool,
}

#[derive(Debug, Parser, Clone, Copy)]
pub enum JwtAlg {
    HS256,
    HS384,
    HS512,
    RS256,
    RS384,
    RS512,
    ES256,
    ES384,
    ES512,
}

#[derive(Debug, Parser)]
pub struct JwtVerifyOpts {
    #[arg(short, long)]
    pub token: String,
    #[arg(long)]
    pub aud: String,
    #[arg(long)]
    pub sub: String,
}

impl FromStr for JwtAlg {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "HS256" => Ok(Self::HS256),
            "HS384" => Ok(Self::HS384),
            "HS512" => Ok(Self::HS512),
            "RS256" => Ok(Self::RS256),
            "RS384" => Ok(Self::RS384),
            "RS512" => Ok(Self::RS512),
            "ES256" => Ok(Self::ES256),
            "ES384" => Ok(Self::ES384),
            "ES512" => Ok(Self::ES512),
            _ => Err("Invalid JWT algorithm"),
        }
    }
}

fn parse_offset_date_time(s: &str) -> Result<OffsetDateTime, &'static str> {
    let unit = &s[s.len() - 1..];
    let i: i64 = s[..s.len() - 1].parse().map_err(|_| "invalid duration")?;
    let dur = match unit {
        "m" => Duration::minutes(i),
        "h" => Duration::hours(i),
        "d" => Duration::days(i),
        _ => return Err("invalid duration unit"),
    };
    Ok(OffsetDateTime::now_utc() + dur)
}

fn parse_jwt_args(s: &str) -> Result<JwtAlg, &'static str> {
    s.parse()
}

impl CmdExector for JwtEncodeOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let claims = JwtClaims {
            aud: self.aud.clone(),
            sub: self.sub.clone(),
            exp: self.exp.unix_timestamp(),
        };

        let token = jwt_encode(&claims, self.alg).await?;
        println!("{}", token);
        Ok(())
    }
}

impl CmdExector for JwtVerifyOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let claims = jwt_verify(&self.token, &self.aud, &self.sub);
        println!("{:?}", claims);
        Ok(())
    }
}
