ARG OPEN_POLICY_AGENT_IMAGE=openpolicyagent/opa:0.70.0
FROM ${OPEN_POLICY_AGENT_IMAGE}

FROM ubuntu
WORKDIR /app
COPY . ./
COPY --from=0 /opa .

RUN /app/opa build /app/policies -o /bundle.tar.gz

FROM ${OPEN_POLICY_AGENT_IMAGE}

COPY --from=1 bundle.tar.gz /bundle.tar.gz

CMD ["run", "-b", "/bundle.tar.gz", "--server", "--log-level=debug"]