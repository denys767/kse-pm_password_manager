package ua.kse.passwordmanager.keys;

import jakarta.validation.Valid;
import java.util.Locale;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import ua.kse.passwordmanager.auth.AuthFacade;
import ua.kse.passwordmanager.common.BadRequestException;
import ua.kse.passwordmanager.common.NotFoundException;

@RestController
@RequestMapping("/api/keys")
public class KeysController {

    private final UserKeysRepository repository;
    private final AuthFacade authFacade;

    public KeysController(UserKeysRepository repository, AuthFacade authFacade) {
        this.repository = repository;
        this.authFacade = authFacade;
    }

    /** Full key record of the current user — used at unlock, incl. on a new device. */
    @GetMapping("/me")
    public UserKeysDto myKeys() {
        String email = authFacade.current().email();
        return repository.findById(email)
                .map(UserKeysDto::from)
                .orElseThrow(() -> new NotFoundException("No keypair registered yet"));
    }

    /**
     * Register or update the caller's keypair. Replacing an existing keypair
     * with a different public key makes previously wrapped item keys
     * unreadable, so it requires an explicit {@code force=true}. Re-uploading
     * the same public key with a re-encrypted private key (passphrase change)
     * is always allowed.
     */
    @PutMapping("/me")
    @Transactional
    public ResponseEntity<UserKeysDto> saveMyKeys(@Valid @RequestBody UserKeysDto dto,
                                                  @RequestParam(defaultValue = "false") boolean force) {
        String email = authFacade.current().email();
        UserKeys keys = repository.findById(email).orElse(null);
        boolean created = keys == null;
        if (keys == null) {
            keys = new UserKeys(email);
        } else if (!keys.getPublicKey().equals(dto.publicKey()) && !force) {
            throw new BadRequestException(
                    "A different keypair is already registered; pass force=true to replace it "
                            + "(existing shared items will become unreadable)");
        }
        keys.setPublicKey(dto.publicKey());
        keys.setEncryptedPrivateKey(dto.encryptedPrivateKey());
        keys.setPrivateKeyIv(dto.privateKeyIv());
        keys.setKdfSalt(dto.kdfSalt());
        keys.setKdfAlgorithm(dto.kdfAlgorithm());
        keys = repository.save(keys);
        return ResponseEntity.status(created ? HttpStatus.CREATED : HttpStatus.OK)
                .body(UserKeysDto.from(keys));
    }

    /** Public key of another user — needed to wrap an item key when sharing. */
    @GetMapping("/{email}")
    public PublicKeyDto publicKey(@PathVariable String email) {
        return repository.findById(email.toLowerCase(Locale.ROOT))
                .map(PublicKeyDto::from)
                .orElseThrow(() -> new NotFoundException(
                        "User has no registered keypair (they must sign in at least once)"));
    }
}
