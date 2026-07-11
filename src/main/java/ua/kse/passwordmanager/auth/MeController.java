package ua.kse.passwordmanager.auth;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/me")
public class MeController {

    private final AuthFacade authFacade;

    public MeController(AuthFacade authFacade) {
        this.authFacade = authFacade;
    }

    @GetMapping
    public CurrentUser me() {
        return authFacade.current();
    }
}
