package pt.unl.fct.di.apdc.firstwebapp.listeners;

import com.google.cloud.datastore.DatastoreOptions;
import com.google.cloud.datastore.Entity;
import com.google.cloud.datastore.Key;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import jakarta.servlet.annotation.WebListener;
import com.google.cloud.datastore.Datastore;
import org.apache.commons.codec.digest.DigestUtils;

@WebListener
public class StartupInitializer implements ServletContextListener {
    private static final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();

    @Override
    public void contextInitialized(ServletContextEvent event) {
        Key rootKey = datastore.newKeyFactory().setKind("User").newKey("root");

        if (datastore.get(rootKey) == null) {
            Entity rootUser = Entity.newBuilder(rootKey)
                    .set("email", "root@admin.pt")
                    .set("userName", "root")
                    .set("name", "System Root Administrator")
                    .set("phoneNum", "+123456789")
                    .set("password", DigestUtils.sha512Hex("Root123!!"))
                    .set("isPublic", false)
                    .set("role", "ADMIN")
                    .set("accountState", "ACTIVE")
                    .build();

            datastore.put(rootUser);
            System.out.println("Conta root criada com sucesso.");
        }
    }

    @Override
    public void contextDestroyed(ServletContextEvent sce) {
        // Is this needed?
    }
}
