export const typeDefs = `#graphql
  enum Role { ADMIN EMPLOYEE }
  enum Status { PENDING IN_TRANSIT DELIVERED }

  type User { id: ID!, email: String!, role: Role! }

  type Shipment {
    id: ID!, trackingId: String!, origin: String!, destination: String!,
    status: Status!, weight: Float!, details: String, createdAt: String!
  }

  type Query {
    me: User
    users: [User!]!
    shipments(status: Status, limit: Int, offset: Int): [Shipment!]!
    shipment(id: ID!): Shipment
  }

  type Mutation {
    login(email: String!, password: String!): User!
    logout: Boolean!
    createEmployee(email: String!, password: String!): User!
    createShipment(trackingId: String!, origin: String!, destination: String!, weight: Float!, details: String): Shipment!
    updateShipmentStatus(id: ID!, status: Status!): Shipment!
    deleteShipment(id: ID!): Boolean!
  }
`;