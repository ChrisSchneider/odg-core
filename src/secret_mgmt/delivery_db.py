import dataclasses


@dataclasses.dataclass(kw_only=True)
class DeliveryDB:
    username: str = 'postgres'
    password: str
    hostname: str | None = None
    port: int = 5432

    def connection_url(
        self,
        namespace: str | None = None,
        service_name: str = 'delivery-db',
        schema: str = 'postgresql+psycopg',
    ) -> str:
        """
        Build a SQLAlchemy connection URL. If `hostname` is set on this instance (external DB),
        `namespace` and `service_name` are ignored. Otherwise `namespace` is required to resolve
        the in-cluster DNS name `<service_name>.<namespace>.svc.cluster.local`.
        """
        if self.hostname:
            hostname = self.hostname
        else:
            if not namespace:
                raise ValueError('namespace is required when no hostname is configured')
            hostname = f'{service_name}.{namespace}.svc.cluster.local'
        return f'{schema}://{self.username}:{self.password}@{hostname}:{self.port}'
