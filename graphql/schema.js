const { buildSchema } = require("graphql");

module.exports = buildSchema(`    
    type Post {
        _id:ID!
        title: String!
        content: String!
        imageUrl: String!
        creator: User!
        createdAt: String!
        updatedAt: String!
    }

    type User {
        _id: ID!
        email: String!
        name: String!
        password: String
        status: String!
        posts: [Post!]!
    }

    input userInputData {
        email: String!
        name: String!
        password: String!
    }    

    type AuthData {
        token: String!
        userId: String!
    }
    
    input PostInputData {
        title: String!
        content: String!
        imageUrl: String!
    }
    
    type RootQuery {
        login(email: String!, password: String! ): AuthData!
    }

    type RootMutation {
        createUser(userInput: userInputData!) : User!
        createPost(postInput: PostInputData!) : Post!
    }

    schema {
        query: RootQuery
        mutation: RootMutation
    }
`);
