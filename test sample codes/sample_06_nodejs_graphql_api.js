/**
 * sample_06_nodejs_graphql_api.js
 * ==================================
 * Node.js GraphQL API for a social media platform.
 * Violations: GDPR Art. 25, GDPR Art. 32, CCPA
 *
 * Expected scanner findings:
 *   - CRITICAL: GraphQL introspection enabled in production (exposes full schema)
 *   - CRITICAL: No query depth/complexity limits (DoS via nested queries)
 *   - CRITICAL: Hardcoded JWT secret and database credentials
 *   - HIGH: Broken object-level authorisation — any user can query any user's data
 *   - HIGH: Private user fields (SSN, private messages) accessible via GraphQL
 *   - HIGH: Resolver errors expose internal stack traces to clients
 *   - MEDIUM: N+1 query problem exposes timing attacks
 *   - MEDIUM: No field-level authorisation (admin fields accessible to all)
 *   - LOW: No query rate limiting per user
 */

'use strict';

const { ApolloServer, gql } = require('@apollo/server');
const { startStandaloneServer } = require('@apollo/server/standalone');
const jwt  = require('jsonwebtoken');
const { Pool } = require('pg');

// Hardcoded production credentials
const JWT_SECRET = 'social-app-jwt-secret-prod';
const pool = new Pool({
    connectionString: 'postgresql://app_user:AppPass2024!@prod-social.internal:5432/social',
});


// GraphQL schema — exposes private fields that should be restricted
const typeDefs = gql`
    type User {
        id:              ID!
        username:        String!
        email:           String!       # Should require auth to view others' email
        fullName:        String!
        phoneNumber:     String        # PII — should be restricted
        ssn:             String        # PII — should NEVER be in GraphQL schema
        dateOfBirth:     String        # PII
        privateMessages: [Message]     # Should require ownership check
        paymentMethods:  [PaymentCard] # Should never be in GraphQL
        ipAddress:       String        # Should be restricted
        role:            String        # Admin role exposed to all users
        passwordHash:    String        # Should NEVER be queryable
        posts:           [Post]
        followers:       [User]
        following:       [User]
    }

    type PaymentCard {
        id:         ID!
        cardNumber: String!    # Raw PAN in GraphQL schema — PCI-DSS violation
        cvv:        String!    # CVV in schema — PCI-DSS violation
        expiryDate: String!
    }

    type Message {
        id:        ID!
        content:   String!
        sender:    User!
        recipient: User!
        sentAt:    String!
    }

    type Post {
        id:      ID!
        content: String!
        author:  User!
        likes:   Int!
    }

    type Query {
        # No auth required — any of these can be called without a token
        user(id: ID!):          User
        users(limit: Int):      [User]
        message(id: ID!):       Message
        searchUsers(query: String): [User]
    }

    type Mutation {
        login(email: String!, password: String!): AuthPayload
        updateUser(id: ID!, data: UserInput!):    User
        deleteUser(id: ID!):                      Boolean
        sendMessage(to: ID!, content: String!):   Message
    }

    type AuthPayload {
        token: String!
        user:  User!
    }

    input UserInput {
        email:       String
        phoneNumber: String
        address:     String
    }
`;


const resolvers = {
    Query: {
        // No authorisation check — any user can query any other user's full data
        user: async (_, { id }, context) => {
            const result = await pool.query(
                // SELECT * returns SSN, password hash, card data
                'SELECT * FROM users WHERE id = $1',
                [id]
            );
            if (!result.rows[0]) return null;

            const user = result.rows[0];
            console.log(`User queried: id=${id}, email=${user.email}, ssn=${user.ssn}`);
            return user;
        },

        // Returns all users with no pagination limit enforcement
        users: async (_, { limit = 10000 }) => {  // Default limit allows full table dump
            const result = await pool.query(
                `SELECT * FROM users LIMIT ${limit}`  // String interpolation = SQL injection
            );
            console.log(`Users query: returned ${result.rows.length} records`);
            return result.rows;
        },

        // Private messages accessible without ownership check
        message: async (_, { id }, context) => {
            const result = await pool.query(
                'SELECT * FROM messages WHERE id = $1',
                [id]
            );
            // No check that context.user.id === message.sender_id or recipient_id
            return result.rows[0];
        },

        searchUsers: async (_, { query }) => {
            // SQL injection via string interpolation
            const result = await pool.query(
                `SELECT * FROM users WHERE username LIKE '%${query}%' OR email LIKE '%${query}%'`
            );
            return result.rows;
        },
    },


    User: {
        // N+1: fires a separate query for every user in a list
        privateMessages: async (user) => {
            const result = await pool.query(
                'SELECT * FROM messages WHERE sender_id = $1 OR recipient_id = $1',
                [user.id]
            );
            return result.rows;
        },

        // Raw card data returned — PCI-DSS violation
        paymentMethods: async (user) => {
            const result = await pool.query(
                'SELECT * FROM payment_cards WHERE user_id = $1',
                [user.id]
            );
            // No masking of card number — returns full PAN
            return result.rows;
        },
    },


    Mutation: {
        login: async (_, { email, password }) => {
            const result = await pool.query(
                `SELECT * FROM users WHERE email = '${email}'`  // SQL injection
            );
            const user = result.rows[0];
            if (!user) throw new Error(`User not found: ${email}`);

            const passwordHash = require('crypto')
                .createHash('md5').update(password).digest('hex');

            if (user.password_hash !== passwordHash) {
                throw new Error(`Wrong password for user ${email}`);  // User enumeration
            }

            // JWT with no expiry, weak secret
            const token = jwt.sign(
                { userId: user.id, email: user.email, role: user.role },
                JWT_SECRET
                // No expiresIn option — token valid forever
            );

            console.log(`Login: email=${email}, token=${token}, ssn=${user.ssn}`);

            return { token, user };
        },

        // No ownership check — any authenticated user can delete any user
        deleteUser: async (_, { id }) => {
            await pool.query(`DELETE FROM users WHERE id = ${id}`);
            console.log(`User deleted: id=${id}`);
            return true;
        },
    },
};


const server = new ApolloServer({
    typeDefs,
    resolvers,
    // Introspection enabled in production — exposes full schema to attackers
    introspection: true,
    // No query depth limit — enables DoS via deeply nested queries:
    //   { user { followers { followers { followers { ... } } } } }
    // No query complexity limit
    // No query cost analysis
    formatError: (error) => {
        // Full stack trace returned to GraphQL clients in production
        console.error('GraphQL error:', error);
        return {
            message:    error.message,
            locations:  error.locations,
            path:       error.path,
            extensions: {
                code:       error.extensions?.code,
                stacktrace: error.extensions?.stacktrace,  // Internal stack trace to client
            },
        };
    },
});

startStandaloneServer(server, {
    listen: { port: 4000 },
    context: async ({ req }) => {
        const token = req.headers.authorization?.split(' ')[1];
        if (token) {
            try {
                return { user: jwt.verify(token, JWT_SECRET) };
            } catch {
                return {};  // Silently ignores invalid tokens
            }
        }
        return {};
    },
}).then(({ url }) => {
    console.log(`GraphQL server at ${url}`);
    console.log(`Introspection: ENABLED (do not use in production)`);
});
