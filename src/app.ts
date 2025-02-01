/**
 * The following lines intialize dotenv,
 * so that env vars from the .env file are present in process.env
**/
import * as dotenv from 'dotenv';
import { PKCS11 } from '@/libraries/pkcs11';
import { getDevices } from '@/processors/get-devices';
import { getPublicKeys, getPrivateKeys, getKeyPair } from '@/processors/get-keypair';
import { ec } from "elliptic"
dotenv.config();

const PIN_CODE = process.env.PIN_CODE || "000000";
async function main() {
  const pkcs11 = new PKCS11();
  const devices = await getDevices(pkcs11);
  const session = await pkcs11.createSession(devices[0].handler, PIN_CODE);

  const publicKeys = getPublicKeys(pkcs11, session);
  const privateKeys = getPrivateKeys(pkcs11, session);
  const keypair = getKeyPair(privateKeys, publicKeys);
  if (!keypair) return console.error("No keypair found");

  const rawMessage = "TEST_MSG";
  console.log(`✅ Selected slot #${keypair.index}`);
  console.log(`🔍 Signing "${rawMessage}" message with P-256 (ECDSA) algorithm`);

  console.log(`=========== Yubikey ===========`);
  const signature = pkcs11.createSignature(session, keypair.privateKey, Buffer.from(rawMessage));
  console.log(`📄 Signature (B64):`, signature.toString("base64"));
  console.log(`📄 Signature (HEX):`, signature.toString("hex"));
  const verify = pkcs11.verifySignature(session, keypair.publicKey, Buffer.from(rawMessage), signature);
  console.log(`📄 Yubikey Verify:`, verify)

  console.log(`=========== Bult-In ===========`);
  const { x, y, raw: ecPoint } = pkcs11.getECPoint(session, keypair.publicKey);
  console.log(`📄 ECPoint:`, ecPoint.toString("hex"))
  console.log(`\x1b[2m   X:`, `(${x.length} bytes)`, x.toString("hex"), '\x1b[0m');
  console.log(`\x1b[2m   Y:`, `(${y.length} bytes)`, y.toString("hex"), '\x1b[0m');

  const EC = new ec("p256");
  
  const key = EC.keyFromPublic({
    x: x.toString("hex"),
    y: y.toString("hex")
  });
  console.log(key.validate().result ? "✅" : "❌", "Key Type:", ecPoint[0] === 0x04 ? "Uncompressed" : "Unknown")

  const { r, s } = pkcs11.parseSignature(signature);
  console.log(`📄 Manual Verify:`, key.verify(Buffer.from(rawMessage), {
    r,
    s
  }))
  
  pkcs11.closeSession(session);
}
main().catch((e) => {
  console.error(e);
  process.exit(1);
})