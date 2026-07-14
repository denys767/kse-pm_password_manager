package ua.kse.passwordmanager.keys;

public record PublicKeyDto(String email, String publicKey) {

    public static PublicKeyDto from(UserKeys keys) {
        return new PublicKeyDto(keys.getEmail(), keys.getPublicKey());
    }
}
