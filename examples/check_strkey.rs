fn main() {
    let id = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
    let strkey = stellar_strkey::Strkey::from_string(id).unwrap();
    match strkey {
        stellar_strkey::Strkey::Contract(c) => {
            println!("Contract bytes: {:?}", c.0);
            // Also compute the base64 of the LedgerKey
            use stellar_xdr::curr::{
                ContractDataDurability, Hash, LedgerKey, LedgerKeyContractData, Limits, ScAddress,
                ScVal, WriteXdr,
            };
            let key = LedgerKey::ContractData(LedgerKeyContractData {
                contract: ScAddress::Contract(Hash(c.0)),
                key: ScVal::LedgerKeyContractInstance,
                durability: ContractDataDurability::Persistent,
            });
            let b64 = key.to_xdr_base64(Limits::none()).unwrap();
            println!("Key base64: {}", b64);
            println!("Key length: {}", b64.len());
        }
        _ => println!("Not a contract!"),
    }
}
