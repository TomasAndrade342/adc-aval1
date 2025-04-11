package pt.unl.fct.di.apdc.firstwebapp.resources;

import com.google.cloud.datastore.*;
import com.google.gson.Gson;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import pt.unl.fct.di.apdc.firstwebapp.util.User;

import java.util.logging.Level;
import java.util.logging.Logger;

@Path("/users")
public class UserResource {

    private static final Logger LOG = Logger.getLogger(RegisterResource.class.getName());
    private static final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();

    private final Gson g = new Gson();

    public UserResource() {}

    @POST
    @Path("/register")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response registerUser(User user) {
        LOG.fine("Attempt to register user: " + user.userName);

        if (!user.isFullyValid()) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Missing or wrong parameter.").build();
        }

        try {
            Key userKey = datastore.newKeyFactory().setKind("User").newKey(user.userName);

            Entity userEntity = user.asEntity(userKey);
            datastore.add(userEntity);
            LOG.info("User registered " + user.userName);
        }
        catch(DatastoreException e) {
            LOG.log(Level.ALL, e.toString());
            return Response.status(Response.Status.BAD_REQUEST).entity(e.getReason()).build();
        }
        return Response.ok().build();
    }
}
