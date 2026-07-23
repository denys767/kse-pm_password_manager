package ua.kse.passwordmanager.attachment;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
class DriveAttachmentConfiguration {
    @Bean @ConditionalOnMissingBean(DriveAttachmentStore.class)
    DriveAttachmentStore unavailableDriveAttachmentStore() { return new UnavailableDriveAttachmentStore(); }
}
