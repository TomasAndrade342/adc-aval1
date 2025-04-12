package pt.unl.fct.di.apdc.firstwebapp.resources;

import com.google.cloud.datastore.*;
import com.google.gson.Gson;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.apache.commons.codec.digest.DigestUtils;
import pt.unl.fct.di.apdc.firstwebapp.util.*;

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

    @POST
    @Path("/login")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response loginUser(LoginData data) {
        LOG.fine("Attempt to login user: " + data.username);

        Key userKey = datastore.newKeyFactory().setKind("User").newKey(data.username);

        Entity user = datastore.get(userKey);

        if (user == null) {
            LOG.warning("Failed login attempt for: " + data.username);
            return Response.status(Response.Status.FORBIDDEN)
                    .entity("Incorrect username or password.")
                    .build();
        }
        else {
            String hashedPassword = user.getString("password");
            if (hashedPassword.equals(DigestUtils.sha512Hex(data.password))) {
                AuthToken2 token = new AuthToken2(data.username, user.getString("role"));
                Key tokenKey = datastore.newKeyFactory().setKind("AuthToken").newKey(data.username);
                Entity tokenEntity = Entity.newBuilder(tokenKey)
                        .set("userName", token.userName)
                        .set("role", token.role)
                        .set("creationDate", token.creationDate)
                        .set("expirationDate", token.expirationDate)
                        .set("magicVal", token.magicVal)
                        .build();

                datastore.put(tokenEntity);

                LOG.info("Login successful by user: " + data.username);
                return Response.ok(g.toJson(token)).build();
            }
            else {
                LOG.warning("Wrong password for: " + data.username);
                return Response.status(Response.Status.FORBIDDEN).entity("Incorrect username or password").build();
            }
        }
    }

    @POST
    @Path("/role")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response changeRole(RoleData data, @Context HttpHeaders headers) {
        LOG.fine("Role change attempt by: " + data.userName);

        String magicVal = headers.getHeaderString("magicVal");

        if (magicVal == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Authentication token is missing.").build();
        }

        Key userKey = datastore.newKeyFactory().setKind("User").newKey(data.userName);
        Key targetKey = datastore.newKeyFactory().setKind("User").newKey(data.targetUserName);

        Entity user = datastore.get(userKey);
        Entity target = datastore.get(targetKey);

        if (user == null || target == null) {
            LOG.warning("Failed login attempt for: " + data.userName);
            return Response.status(Response.Status.FORBIDDEN)
                    .entity("User(s) don't exist.")
                    .build();
        }
        else if (user.getString("role").equals("ENDUSER") || user.getString("role").equals("PARTNER")) {
            LOG.warning("Failed login attempt for: " + data.userName);
            return Response.status(Response.Status.FORBIDDEN)
                    .entity("Not allowed to change role.")
                    .build();
        }
        else if (user.getString("role").equals("BACKOFFICE") && !data.role.equals("ENDUSER") && !data.role.equals("PARTNER")) {
            LOG.warning("Failed login attempt for: " + data.userName);
            return Response.status(Response.Status.FORBIDDEN)
                    .entity("Invalid operation for backoffice.")
                    .build();
        }
        else {
            Key tokenKey = datastore.newKeyFactory().setKind("AuthToken").newKey(data.userName);
            Entity tokenEntity = datastore.get(tokenKey);

            if (tokenEntity == null || !magicVal.equals(tokenEntity.getString("magicVal"))) {
                return Response.status(Response.Status.FORBIDDEN).entity("Token is wrong.").build();
            }
            long expirationDate = tokenEntity.getLong("expirationDate");
            if (expirationDate < System.currentTimeMillis()) {
                return Response.status(Response.Status.FORBIDDEN).entity("Token expired.").build();
            }
            else {
                Entity newRoleUser = Entity.newBuilder(target)
                        .set("role", data.role)
                        .build();
                datastore.put(newRoleUser);
                LOG.info("Role update successful by user: " + data.userName);
                return Response.ok().build();
            }
        }
    }
}
