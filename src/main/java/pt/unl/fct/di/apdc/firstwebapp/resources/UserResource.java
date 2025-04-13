package pt.unl.fct.di.apdc.firstwebapp.resources;

import com.google.cloud.datastore.*;
import com.google.gson.Gson;
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

import java.util.ArrayList;
import java.util.List;
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
            return Response.status(Response.Status.BAD_REQUEST).entity("Missing or wrong parameters.").build();
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

        if (user.getString("role").equals("ENDUSER") || user.getString("role").equals("PARTNER")) {
            LOG.warning("Failed login attempt for: " + data.userName);
            return Response.status(Response.Status.FORBIDDEN)
                    .entity("Not allowed for current role.")
                    .build();
        }

        if (user.getString("role").equals("BACKOFFICE")) {
            String targetRole = target.getString("role");
            String newRole = data.role;

            boolean targetHasValidRole = targetRole.equals("ENDUSER") || targetRole.equals("PARTNER");
            boolean newRoleIsValid = newRole.equals("ENDUSER") || newRole.equals("PARTNER");

            // If either the current state or the requested state is invalid, reject the operation
            if (!targetHasValidRole || !newRoleIsValid) {
                LOG.warning("Invalid role change attempt by user: " + data.userName);
                return Response.status(Response.Status.FORBIDDEN)
                        .entity("Invalid operation for backoffice.")
                        .build();
            }
        }

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

    @POST
    @Path("/state")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response changeState(StateData data, @Context HttpHeaders headers) {
        LOG.fine("State change attempt by: " + data.userName);

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

        if (!user.getString("role").equals("ADMIN") && !user.getString("role").equals("BACKOFFICE")) {
            LOG.warning("Failed login attempt for: " + data.userName);
            return Response.status(Response.Status.FORBIDDEN)
                    .entity("Not allowed for current role.")
                    .build();
        }

        if (user.getString("role").equals("BACKOFFICE")) {
            String targetState = target.getString("accountState");
            String newState = data.state;

            boolean targetHasValidState = targetState.equals("ACTIVE") || targetState.equals("DEACTIVATED");
            boolean newStateIsValid = newState.equals("ACTIVE") || newState.equals("DEACTIVATED");

            // If either the current state or the requested state is invalid, reject the operation
            if (!targetHasValidState || !newStateIsValid) {
                LOG.warning("Invalid state change attempt by BACKOFFICE user: " + data.userName);
                return Response.status(Response.Status.FORBIDDEN)
                        .entity("Invalid operation for backoffice.")
                        .build();
            }
        }

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
                    .set("accountState", data.state)
                    .build();
            datastore.put(newRoleUser);
            LOG.info("State update successful by user: " + data.userName);
            return Response.ok().build();
        }
    }

    @POST
    @Path("/remove")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response removeUser(RemoveData data, @Context HttpHeaders headers) {
        LOG.fine("User removal attempt by: " + data.userName);

        String magicVal = headers.getHeaderString("magicVal");
        if (magicVal == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Authentication token is missing.").build();
        }

        Key userKey = datastore.newKeyFactory().setKind("User").newKey(data.userName);
        Entity user = datastore.get(userKey);

        if (user == null) {
            LOG.warning("Failed login attempt for: " + data.userName);
            return Response.status(Response.Status.FORBIDDEN)
                    .entity("User doesn't exist.")
                    .build();
        }

        if (!user.getString("role").equals("ADMIN") && !user.getString("role").equals("BACKOFFICE")) {
            LOG.warning("Failed login attempt for: " + data.userName);
            return Response.status(Response.Status.FORBIDDEN)
                    .entity("Not allowed for current role.")
                    .build();
        }

        Key targetKey;
        Entity target;

        if (data.targetUserName == null) {
            if (data.email == null) {
                LOG.warning("Failed user removal attempt for: " + data.userName);
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity("No username or email.")
                        .build();
            }

            Query<Entity> query = Query.newEntityQueryBuilder()
                    .setKind("User")
                    .setFilter(StructuredQuery.PropertyFilter.eq("email", data.email))
                    .build();
            QueryResults<Entity> results = datastore.run(query);

            if (!results.hasNext()) {
                LOG.warning("Failed user removal attempt for: " + data.userName);
                return Response.status(Response.Status.NOT_FOUND)
                        .entity("No user with email")
                        .build();
            }
            target = results.next();
            targetKey = target.getKey();
        }
        else {
            targetKey = datastore.newKeyFactory().setKind("User").newKey(data.targetUserName);
            target = datastore.get(targetKey);
        }

        if (user.getString("role").equals("BACKOFFICE") &&
                !target.getString("role").equals("ENDUSER") && !target.getString("role").equals("PARTNER")) {
            LOG.warning("Failed login attempt for: " + data.userName);
            return Response.status(Response.Status.FORBIDDEN)
                    .entity("Invalid operation for backoffice.")
                    .build();
        }

        datastore.delete(targetKey);

        Key tokenKey = datastore.newKeyFactory().setKind("AuthToken").newKey(target.getString("userName"));
        datastore.delete(tokenKey);
        LOG.info("User removal successful by user: " + data.userName);
        return Response.ok().build();
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response listUsers(ListUsersData data, @Context HttpHeaders headers) {
        LOG.fine("Users list attempt by: " + data.userName);

        String magicVal = headers.getHeaderString("magicVal");
        if (magicVal == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Authentication token is missing.").build();
        }

        Key userKey = datastore.newKeyFactory().setKind("User").newKey(data.userName);
        Entity user = datastore.get(userKey);

        if (user == null) {
            LOG.warning("Failed login attempt for: " + data.userName);
            return Response.status(Response.Status.FORBIDDEN)
                    .entity("User doesn't exist.")
                    .build();
        }

        String role = user.getString("role");
        switch(role) {
            case "ENDUSER":
                Query<Entity> query = Query.newEntityQueryBuilder()
                        .setKind("User")
                        .setFilter(StructuredQuery.CompositeFilter.and(
                                StructuredQuery.PropertyFilter.eq("role", "ENDUSER"),
                                StructuredQuery.PropertyFilter.eq("isPublic", true),
                                StructuredQuery.PropertyFilter.eq("accountState", "ACTIVE")
                        ))
                        .build();
                QueryResults<Entity> results = datastore.run(query);

                List<FilteredUser> filteredUsers = new ArrayList<>();
                results.forEachRemaining(result -> {
                    FilteredUser newUser = new FilteredUser(result.getString("userName"), result.getString("email"), result.getString("fullName"));
                    filteredUsers.add(newUser);
                });

                return Response.ok(g.toJson(filteredUsers)).build();
            case "BACKOFFICE":
                query = Query.newEntityQueryBuilder()
                        .setKind("User")
                        .setFilter(StructuredQuery.PropertyFilter.eq("role", "ENDUSER"))
                        .build();
                results = datastore.run(query);

                List<JsonUser> users = new ArrayList<>();
                results.forEachRemaining(result -> {
                    JsonUser newUser = new JsonUser(result);
                    users.add(newUser);
                });

                return Response.ok(g.toJson(users)).build();
            case "ADMIN":
                query = Query.newEntityQueryBuilder()
                        .setKind("User")
                        .build();
                results = datastore.run(query);

                users = new ArrayList<>();
                results.forEachRemaining(result -> {
                    JsonUser newUser = new JsonUser(result);
                    users.add(newUser);
                });

                return Response.ok(g.toJson(users)).build();
            default:
                LOG.warning("Failed users list attempt for: " + data.userName);
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity("Not allowed for current role.")
                        .build();
        }
    }

    // userName of the user using the endpoint must be inserted into the headers
    @POST
    @Path("/update")
    public Response updateUser(User user, @Context HttpHeaders headers) {
        LOG.fine("Attempt to modify user: " + user.userName);

        String magicVal = headers.getHeaderString("magicVal");
        if (magicVal == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Authentication token is missing.").build();
        } // TODO: actually verify if magicVal is equal to magicVal of the operator and that token is valid everywhere
        // TODO: check if all involved users are in the db

        String operatorUserName = headers.getHeaderString("userName");
        Key operatorKey = datastore.newKeyFactory().setKind("User").newKey(operatorUserName);
        Entity operator = datastore.get(operatorKey);

        if (!user.fieldsAreValid()) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Missing or wrong parameters.").build();
        }

        String targetUserName = headers.getHeaderString("targetUserName");
        Key targetKey = datastore.newKeyFactory().setKind("User").newKey(targetUserName);
        Entity target = datastore.get(targetKey);

        if (target == null) {
            LOG.warning("Failed update attempt for: " + operatorUserName);
            return Response.status(Response.Status.FORBIDDEN)
                    .entity("Target isn't registered.")
                    .build();
        }



        String role = operator.getString("role");
        switch (role) {
            case "ENDUSER":
                if (operator.getString("userName").equals(targetUserName)) {
                    if (user.userName != null || user.email != null || user.fullName != null || user.role != null
                            || user.accountState != null) {
                        LOG.warning("Failed update attempt for: " + operatorUserName);
                        return Response.status(Response.Status.FORBIDDEN)
                                .entity("Fields can't be updated.")
                                .build();
                    }
                    else {
                        datastore.put(user.getUpdatedUser(target));

                        LOG.info("Login successful by user: " + operatorUserName);
                        return Response.ok().build();
                    }
                }
                else {
                    LOG.warning("Failed update attempt for: " + targetUserName);
                    return Response.status(Response.Status.FORBIDDEN)
                            .entity("Can't modify a different account.")
                            .build();
                }
            case "BACKOFFICE":
                boolean targetValidRole = target.getString("role").equals("ENDUSER") || target.getString("role").equals("PARTNER");
                if (!operator.getString("accountState").equals("ACTIVE") || ! targetValidRole ||
                    user.userName != null || user.email != null || user.role.equals("SUSPENDED")) {
                    LOG.warning("Failed update attempt for: " + targetUserName);
                    return Response.status(Response.Status.FORBIDDEN)
                            .entity("Invalid operation for backoffice.")
                            .build();
                }
                else {
                    datastore.put(user.getUpdatedUser(target));

                    LOG.info("Successful update attempt for: " + targetUserName);
                    return Response.ok().build();
                }
            case "ADMIN":
                datastore.put(user.getUpdatedUser(target));

                LOG.info("Successful update attempt for: " + targetUserName);
                return Response.ok().build();
            default:
                LOG.warning("Failed update attempt for: " + targetUserName);
                return Response.status(Response.Status.FORBIDDEN)
                        .entity("Not allowed for current role.")
                        .build();
        }
    }

    @POST
    @Path("/password")
    public Response changePassword(ChangePassData data, @Context HttpHeaders headers) {
        LOG.fine("Attempt to change password by: " + data.userName);

        String magicVal = headers.getHeaderString("magicVal");
        if (magicVal == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Authentication token is missing.").build();
        }

        Key userKey = datastore.newKeyFactory().setKind("User").newKey(data.userName);
        Entity user = datastore.get(userKey);

        if (user == null || !user.getString("password").equals(DigestUtils.sha512Hex(data.password))) {
            LOG.warning("Failed password change attempt for: " + data.userName);
            return Response.status(Response.Status.FORBIDDEN)
                    .entity("Incorrect username or password.")
                    .build();
        }
        else if (!data.newPassword.equals(data.newPasswordAgain)) {
            LOG.warning("Failed password change attempt for: " + data.userName);
            return Response.status(Response.Status.FORBIDDEN)
                    .entity("Passwords don't match.")
                    .build();
        }
        else {
            Entity newPassUser = Entity.newBuilder(user)
                    .set("password", DigestUtils.sha512Hex(data.newPassword))
                    .build();
            datastore.put(newPassUser);
            LOG.info("Password change successful by user: " + data.userName);
            return Response.ok().build();
        }
    }
}
