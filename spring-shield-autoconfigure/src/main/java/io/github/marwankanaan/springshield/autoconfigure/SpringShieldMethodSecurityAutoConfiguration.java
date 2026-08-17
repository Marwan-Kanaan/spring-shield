package io.github.marwankanaan.springshield.autoconfigure;

import io.github.marwankanaan.springshield.RequiresPermission;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.annotation.AnnotationTemplateExpressionDefaults;

/**
 * Turns on the method security that makes {@link RequiresPermission} and
 * {@code @RequiresRole} take effect.
 *
 * <p>
 * This class is internal and not a supported extension point.
 *
 * <h2>What it actually does</h2>
 *
 * <p>
 * Two things, both small:
 *
 * <ul>
 * <li>{@link EnableMethodSecurity} switches on Spring Security's method authorization,
 * the same mechanism behind {@code @PreAuthorize}.</li>
 * <li>{@link AnnotationTemplateExpressionDefaults} lets a meta-annotation expand a
 * placeholder, which is what turns {@code @RequiresPermission("invoice.read")} into
 * {@code hasAuthority('invoice.read')}. Without this bean the {@code {value}} placeholder
 * is never substituted and the annotations do not work.</li>
 * </ul>
 *
 * <p>
 * SpringShield contributes no authorization logic of its own. Enforcement is entirely
 * Spring Security's.
 *
 * <h2>Turning it off</h2>
 *
 * <p>
 * Set {@code springshield.authorization.enabled=false}.
 *
 * <p>
 * Be careful with that. It does not relax an individual rule; it stops the annotations
 * being enforced at all, so a method that still reads as guarded runs unguarded. Prefer
 * removing an annotation you no longer want over disabling the mechanism that enforces
 * all of them.
 *
 * <h2>Applying it yourself</h2>
 *
 * <p>
 * An application that declares its own {@code @EnableMethodSecurity} keeps working.
 * Spring registers the imported configuration once regardless of how many places request
 * it, so the two do not conflict. The {@link AnnotationTemplateExpressionDefaults} bean
 * backs off if the application supplies one.
 *
 * @author mkanaan
 */
@AutoConfiguration(after = SpringShieldAutoConfiguration.class)
@ConditionalOnClass({ PreAuthorize.class, EnableMethodSecurity.class })
@ConditionalOnProperty(prefix = "springshield.authorization", name = "enabled", havingValue = "true",
		matchIfMissing = true)
@EnableMethodSecurity
public class SpringShieldMethodSecurityAutoConfiguration {

	/**
	 * Creates the auto-configuration. Spring calls this; application code should not.
	 */
	public SpringShieldMethodSecurityAutoConfiguration() {
	}

	/**
	 * Enables placeholder expansion in security meta-annotations.
	 *
	 * <p>
	 * This is what allows {@code @RequiresPermission("invoice.read")} to resolve to the
	 * expression {@code hasAuthority('invoice.read')}. Without it the annotations are
	 * present but never enforce anything.
	 *
	 * <p>
	 * Declared {@code static} because it takes part in configuration processing and must
	 * be instantiated early, before the bean factory is fully initialized.
	 * @return the template defaults
	 */
	@Bean
	@ConditionalOnMissingBean
	static AnnotationTemplateExpressionDefaults springShieldAnnotationTemplateExpressionDefaults() {
		return new AnnotationTemplateExpressionDefaults();
	}

}
