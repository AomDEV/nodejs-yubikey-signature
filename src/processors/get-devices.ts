import { DeviceHandler, PKCS11 } from "@/libraries/pkcs11";

export async function getDevices (
    pkcs11: PKCS11
) {
    const slots = await pkcs11.getSlots();
    return Promise.all(slots.map((handler: DeviceHandler) => {
        const slot = pkcs11.getSlot(handler);
        const token = pkcs11.getToken(handler);

        return { slot, token, handler };
    }))
    
}