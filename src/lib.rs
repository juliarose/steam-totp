use std::time::{SystemTime, UNIX_EPOCH};
use sha1::Sha1;
use hmac::{Hmac, Mac, NewMac};
use std::io::Cursor;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use base64;

const CHARS: &'static [char] = &['2', '3', '4', '5', '6', '7', '8', '9', 'B', 'C', 'D', 'F', 'G', 'H', 'J', 'K', 'M', 
'N', 'P', 'Q', 'R', 'T', 'V', 'W', 'X', 'Y'];

// Create alias for HMAC-SHA1
type HmacSha1 = Hmac<Sha1>;

pub fn generate_auth_code(secret: String) -> Result<String, std::io::Error> {
    generate_auth_code_for_time(secret, current_time())
}

pub fn generate_auth_code_for_time(secret: String, time: u32) -> Result<String, std::io::Error> {
    let mut full_code = {
        let hmac = get_hmac(secret, time)?;
        let result = hmac.finalize().into_bytes();
        let slice_start = result[19] & 0x0F;
        let slice_end = slice_start + 4;
        let slice: &[u8] = &result[slice_start as usize..slice_end as usize];
        let full_code_bytes = Cursor::new(&slice).read_u32::<BigEndian>()?;
        
        full_code_bytes & 0x7FFFFFFF
    };
    let chars_len = CHARS.len() as u32;
    let code = (0..5).map(|_i| {
        let char_code = CHARS[(full_code % chars_len) as usize];
        
        full_code = full_code / chars_len;
        
        char_code
    }).collect::<String>();
    
    Ok(code)
}

pub fn current_time() -> u32 {
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)
        .expect("System time is set to before unix epoch");
    
    timestamp.as_secs() as u32
}

fn get_hmac(secret: String, time: u32) -> Result<HmacSha1, std::io::Error> {
    let decoded = base64::decode(secret)
        .expect("Secret can not be decoded to base64");
    let mut mac = HmacSha1::new_from_slice(&decoded[..])
        .expect("HMAC can take key of any size");
    let mut buf = Cursor::new(vec![0u8; 8]);
    
    buf.write_u32::<BigEndian>(0)?;
    buf.write_u32::<BigEndian>(time / 30)?;
    
    let bytes: &[u8] = buf.get_ref();
    
    mac.update(bytes);
    
    Ok(mac)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn time_works() {
        assert!(current_time() > 0);
    }
    
    #[test]
    fn generating_a_code_works() {
        let secret = String::from("000000000000000000000000000=");
        let time: u32 = 1634603498;
        let code = generate_auth_code_for_time(secret, time).unwrap();
        
        assert_eq!(code, "2C5H2");
    }
}
