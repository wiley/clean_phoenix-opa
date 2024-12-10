FROM openpolicyagent/opa:0.70.0
#opa image is a "distroless" that only contains the /opa binary
#we need to move it to a ubuntu image to have the other tools
FROM ubuntu
WORKDIR /app
#RUN mkdir policies
COPY --from=0 /opa .
ENTRYPOINT ["/app/opa"]
CMD ["run", "/policies", "--watch", "--server", "--disable-telemetry", "--log-level=debug"]