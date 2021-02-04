package severeone.oidc.auth.core.email;

import severeone.email.EmailServicesExtension;

import java.time.ZonedDateTime;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

public class EmailServicesExtensionImpl implements EmailServicesExtension {
    @Override
    public boolean checkBounces() {return false;}
    @Override
    public Optional<ZonedDateTime> getLastEmailEventsCheck() {return Optional.empty();}
    @Override
    public CompletableFuture<Integer> setLastEmailEventsCheck(ZonedDateTime date) {return CompletableFuture.completedFuture(0);}
    @Override
    public CompletableFuture<Integer> disableEmailNotificationForUsers(List<String> emails, boolean full) {return CompletableFuture.completedFuture(0);}
}
