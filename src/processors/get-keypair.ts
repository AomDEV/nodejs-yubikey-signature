import { PKCS11, pkcs11js, Session } from "@/libraries/pkcs11";
import _ from "lodash";

function getClass (
    pkcs11: PKCS11,
    session: Session,
    value: number
) {
    return _.range(20).map(index => {
        const object = pkcs11.getObject(session, [
            {
                type: pkcs11js.CKA_ID,
                value: Buffer.from([index])
            },
            {
                type: pkcs11js.CKA_CLASS,
                value,
            },
        ]);
        if (!object) return null;

        return { index, object };
    }).filter(Boolean) as Array<{
        readonly index: number;
        readonly object: pkcs11js.Handle;
    }>;
}
export function getPrivateKeys (
    pkcs11: PKCS11,
    session: Session,
) {
    return getClass(pkcs11, session, pkcs11js.CKO_PRIVATE_KEY)
}
export function getPublicKeys (
    pkcs11: PKCS11,
    session: Session,
) {
    return getClass(pkcs11, session, pkcs11js.CKO_PUBLIC_KEY)
}
export function getCertificates (
    pkcs11: PKCS11,
    session: Session,
) {
    return getClass(pkcs11, session, pkcs11js.CKO_CERTIFICATE)
}
export function getKeyPair (
    privateKeys: ReturnType<typeof getClass>,
    publicKeys: ReturnType<typeof getClass>,
    certificates?: ReturnType<typeof getClass>,
) {
    const publicKeyObj = _.first(publicKeys);
    const privateKeyObj = _.first(privateKeys);
    if (!publicKeyObj || !privateKeyObj) return null;
    if (publicKeyObj.index !== privateKeyObj.index) return null;
    if (certificates) {
        const certificateObj = _.first(certificates)!;
        if (publicKeyObj.index !== certificateObj.index) return null;
    }

    const publicKey = publicKeyObj.object;
    const privateKey = privateKeyObj.object;
    const certificate = _.first(certificates)?.object;
    
    // random pick index
    const index = _.first(_.shuffle([publicKeyObj.index, privateKeyObj.index]))
    return { publicKey, privateKey, index, certificate }
}