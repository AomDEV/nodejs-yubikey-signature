import _ from "lodash";
import pkcs11js from "pkcs11js";

export type DeviceHandler = pkcs11js.Handle;
export type Session = pkcs11js.Handle;
export { pkcs11js };

const LIB_PATH = "/opt/homebrew/Cellar/yubico-piv-tool/2.7.1/lib/libykcs11.dylib";
export class PKCS11 {
    public readonly pkcs11: pkcs11js.PKCS11 = new pkcs11js.PKCS11()
    constructor(
        private readonly libPath: string = LIB_PATH
    ) {
        this.pkcs11.load(this.libPath);
        try {
            this.pkcs11.C_Initialize();
        } catch { }
    }

    public getSlots() {
        return this.pkcs11.C_GetSlotList(true);
    }

    public getSlot(slot: pkcs11js.Handle) {
        return this.pkcs11.C_GetSlotInfo(slot);
    }

    public getToken(slot: pkcs11js.Handle) {
        return this.pkcs11.C_GetTokenInfo(slot);
    }

    public getMechanismList(slot: pkcs11js.Handle) {
        return this.pkcs11.C_GetMechanismList(slot);
    }

    public getMechanismInfo(slot: pkcs11js.Handle, mech: number) {
        return this.pkcs11.C_GetMechanismInfo(slot, mech);
    }

    public createSession(slot: pkcs11js.Handle, pinCode?: string) {
        const session = this.pkcs11.C_OpenSession(slot, pkcs11js.CKF_SERIAL_SESSION | pkcs11js.CKF_RW_SESSION);
        if (pinCode) this.pkcs11.C_Login(session, pkcs11js.CKU_USER, pinCode);
        return session;
    }

    public getObjects(session: pkcs11js.Handle, template: pkcs11js.Template, count: number = 10) {
        this.pkcs11.C_FindObjectsInit(session, template);
        const objects = this.pkcs11.C_FindObjects(session, count);
        this.pkcs11.C_FindObjectsFinal(session);
        return objects;
    }

    public getObject(session: pkcs11js.Handle, template: pkcs11js.Template) {
        return _.first(this.getObjects(session, template));
    }

    public closeSession(session: pkcs11js.Handle) {
        this.pkcs11.C_Logout(session);
        this.pkcs11.C_CloseSession(session);
    }

    public createSignature(
        session: pkcs11js.Handle,
        privateKey: pkcs11js.Handle,
        message: Buffer,
        mechanism: number = pkcs11js.CKM_ECDSA
    ) {
        this.pkcs11.C_SignInit(session, { mechanism }, privateKey);
        this.pkcs11.C_SignUpdate(session, message);
        return this.pkcs11.C_SignFinal(session, Buffer.alloc(256));
    }

    public verifySignature(
        session: pkcs11js.Handle,
        publicKey: pkcs11js.Handle,
        message: Buffer,
        signature: Buffer,
        mechanism: number = pkcs11js.CKM_ECDSA
    ) {
        this.pkcs11.C_VerifyInit(session, { mechanism }, publicKey);
        this.pkcs11.C_VerifyUpdate(session, message);
        return this.pkcs11.C_VerifyFinal(session, signature);
    }

    public getECPoint (session: pkcs11js.Handle, object: pkcs11js.Handle) {
        const attribute = this.pkcs11.C_GetAttributeValue(session, object, [
            { type: pkcs11js.CKA_EC_POINT },
        ]);
        const [ecPointAttr] = attribute; 

        const raw = ecPointAttr.value;
        const x = raw.subarray(3, 35);
        const y = raw.subarray(35);

        return {
            raw,
            x,
            y,
        }
    }

    public parseSignature (signature: Buffer) {
        const sigLength = signature.length / 2;
        const r = signature.subarray(0, sigLength);
        const s = signature.subarray(sigLength);
        const buffer = signature;
        
        return { r, s, buffer };
    }
}