package ua.kse.passwordmanager.common;

/** A resource which deliberately existed but is no longer available. */
public class GoneException extends RuntimeException {
    public GoneException(String message) {
        super(message);
    }
}
