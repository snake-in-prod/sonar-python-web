import graphene


class Query(graphene.ObjectType):
    hello = graphene.String()


schema = graphene.Schema(query=Query)
