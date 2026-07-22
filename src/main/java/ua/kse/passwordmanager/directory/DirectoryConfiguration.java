package ua.kse.passwordmanager.directory;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
class DirectoryConfiguration {
    @Bean
    @ConditionalOnMissingBean(WorkspaceDirectoryClient.class)
    WorkspaceDirectoryClient unavailableWorkspaceDirectoryClient() {
        return new UnavailableWorkspaceDirectoryClient();
    }
}
