package id.co.swipepay.apigateway.config.translator;

import id.co.swipepay.utils.Translator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.ResourceBundleMessageSource;

@Configuration
public class TranslatorConfig {

    @Bean
    public Translator messageTranslator(){
        return new Translator(messageSource());
    }

    public ResourceBundleMessageSource messageSource() {
        ResourceBundleMessageSource resource = new ResourceBundleMessageSource();
        resource.setBasename("messages");
        resource.setUseCodeAsDefaultMessage(true);
        return resource;
    }
}
