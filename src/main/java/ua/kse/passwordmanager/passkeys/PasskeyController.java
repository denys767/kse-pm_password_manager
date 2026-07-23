package ua.kse.passwordmanager.passkeys;

import jakarta.validation.Valid;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import ua.kse.passwordmanager.auth.AuthFacade;
import ua.kse.passwordmanager.common.ForbiddenException;

@RestController
@RequestMapping("/api/passkeys")
public class PasskeyController {
    private final PasskeyService service; private final AuthFacade auth;
    public PasskeyController(PasskeyService service, AuthFacade auth) { this.service = service; this.auth = auth; }
    private void extensionOnly() { if (!auth.isExtensionClient()) throw new ForbiddenException("Passkey material is available only to the extension OAuth client and audience"); }
    @PostMapping @ResponseStatus(HttpStatus.CREATED)
    public PasskeyDtos.Response create(@Valid @RequestBody PasskeyDtos.CreateRequest request) { extensionOnly(); return service.create(auth.current(), request); }
    @GetMapping
    public List<PasskeyDtos.Response> matching(@RequestParam String rpId) { extensionOnly(); return service.matching(auth.current(), rpId); }
    @PostMapping("/{id}/counter") @ResponseStatus(HttpStatus.NO_CONTENT)
    public void counter(@PathVariable UUID id, @RequestBody PasskeyDtos.CounterRequest request) { extensionOnly(); service.advanceCounter(auth.current(), id, request.signCounter()); }
    @PutMapping("/{id}/wrapped-keys") @ResponseStatus(HttpStatus.NO_CONTENT)
    public void wrappedKey(@PathVariable UUID id, @Valid @RequestBody PasskeyDtos.WrappedKeyRequest request) { extensionOnly(); service.putWrappedKey(auth.current(), id, request); }
}
