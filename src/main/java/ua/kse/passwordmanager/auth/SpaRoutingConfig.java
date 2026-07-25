package ua.kse.passwordmanager.auth;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * History-API fallback for the single-page client.
 *
 * The SPA is served from classpath:/static, so Spring only resolves "/" to
 * index.html; a deep link such as /share/&lt;uuid&gt; matched no controller and no
 * static resource and answered 404 in production. It worked in development
 * purely because the Vite dev server has its own history fallback, which is why
 * every external share link — one-time links in particular — was dead once
 * deployed behind nginx.
 *
 * Only the concrete client routes are forwarded. A blanket /** fallback would
 * turn genuine API and static 404s into HTML, which hides bugs and breaks the
 * extension's error handling.
 */
@Configuration
class SpaRoutingConfig implements WebMvcConfigurer {
    @Override public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/share/{shareId}").setViewName("forward:/index.html");
    }
}
