# AsconDeployment Application

This deployment was auto-generated by the F' utility tool.

## Building and Running the AsconDeployment Application

In order to build the AsconDeployment application, or any other F´ application, we first need to generate a build directory. This can be done with the following commands:

```
cd AsconDeployment
fprime-util generate
```

The next step is to build the AsconDeployment application's code.
```
fprime-util build
```

## Running the application and F' GDS

The following command will spin up the F' GDS as well as run the application binary and the components necessary for the GDS and application to communicate.

```
cd AsconDeployment
fprime-gds
```

To run the ground system without starting the AsconDeployment app:
```
cd AsconDeployment
fprime-gds --no-app
```

The application binary may then be run independently from the created 'bin' directory.

```
cd AsconDeployment/build-artifacts/<platform>/bin/
./AsconDeployment -a 127.0.0.1 -p 50000
```
