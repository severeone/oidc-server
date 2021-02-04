#!/usr/bin/python

import argparse
import os
import subprocess
import sys
import time

import docker
from docker.errors import APIError
from docker.utils import kwargs_from_env

# DB Locations
LOCATION = ''
PRODUCTION = 'production'
STAGING = 'staging'
LOCAL = 'local'

# Work modes
MODE = ''
TEST = 'test'
CHANGE = 'change'

# Commands
START = 'start'
STOP = 'stop'
RESTART = 'restart'
DROP = 'drop'
REINSTALL = 'reinstall'
DESTROY = 'destroy'
STATUS = 'status'
HOST = 'host'

# DB names
DB_NAME = ''
MAIN_DB = 'oidc'
TEST_DB = 'oidc_test'
POSTGRES_DB = 'postgres'

# Debug mode
DEBUG = False

# Paths
ROOT_DIR = ''
DATA_DIR = ''
DB_HOST = ''
STAGING_HOST = '127.0.0.1'
PRODUCTION_HOST = '127.0.0.1'
LOCAL_HOST = '127.0.0.1'
DB_PORT = '5432'
STAGING_PORT = '6432'
PRODUCTION_PORT = '5432'
LOCAL_PORT = '7432'
SECRETS_DIR = ''

# Credentials
DB_USER = 'oidcuser'
DB_PASS = ''
ADMIN_DB_USER = ''
ADMIN_DB_PASS = ''
LOCAL_CHANGE_PASS = 'oidcpwd'
LOCAL_ADMIN_USER = 'postgres'
LOCAL_ADMIN_PASS = ''
REMOTE_ADMIN_USER = 'admin'

# Local DB variables
DB_CONTAINER = os.getenv('OIDC_PSQL_CONTAINER', 'auth-db')
DB_CONFIGS = {
    LOCAL: {MAIN_DB: 'development', TEST_DB: 'dev_integration'},
    STAGING: {MAIN_DB: 'staging', TEST_DB: 'staging_integration'},
    PRODUCTION: {MAIN_DB: 'production', TEST_DB: 'prod_integration'},
}
RETRIES = 10

# Docker
# Note that if you want to use a local registry, then explicitly setting
# DOCKER_REGISTRY to an empty string works fine.
REGISTRY = os.getenv("DOCKER_REGISTRY", "")
DOCKER_TAG = os.getenv("DOCKER_TAG", "10.5-alpine")
PSQL_CONTAINER_IMAGE = "postgres"
if REGISTRY:
    PSQL_CONTAINER_IMAGE = REGISTRY + "/" + PSQL_CONTAINER_IMAGE


def run_psql_cmd(c, cmd, db, user, password):
    cmd = 'psql --host=%s --port=%s --user=%s %s --command "%s"' % (
        DB_HOST, DB_PORT, user, db, cmd
    )

    if LOCATION != LOCAL:
        try_pull(PSQL_CONTAINER_IMAGE, tag=DOCKER_TAG)

    if DEBUG:
        print "Running PSQL command: " + cmd

    # Create temp container to run a command from it
    if LOCATION == LOCAL:
        container = c.create_container(
            PSQL_CONTAINER_IMAGE + ":" + DOCKER_TAG,
            command=cmd,
            environment={"PGPASSWORD": password},
            networking_config=c.create_networking_config({
                'oidcnet': c.create_endpoint_config(ipv4_address='172.8.0.111')
            })
        )
    else:
        container = c.create_container(
            PSQL_CONTAINER_IMAGE + ":" + DOCKER_TAG,
            command=cmd,
            environment={"PGPASSWORD": password},
        )

    cid = container["Id"]
    # start temp container
    c.start(container["Id"])

    # wait for tmp container
    c.wait(cid)
    s = c.inspect_container(cid)["State"]["ExitCode"]
    if DEBUG:
        print(c.logs(cid))

    # remove temp container
    try:
        c.remove_container(cid)
    except APIError as err:
        print >> sys.stderr, "Error encountered while executing command, ignoring."
        if DEBUG:
            print err
        pass

    # running too close together on linux causes issues...
    return s == 0


# Run goose for data migrations
def goose():
    g = os.path.join(ROOT_DIR, "tools", "bin", "goose")
    if not os.path.isfile(g):
        raise ValueError("goose binary not found!")
    path = '-path=%s' % os.path.join(ROOT_DIR, "db", "oidc")
    env = '-env=%s' % DB_CONFIGS[LOCATION][DB_NAME]
    cmd = [g, env, path, "up"]
    if DEBUG:
        print "Running command: " + " ".join(cmd)
    print subprocess.check_output(cmd)


# Bring the db schema up to date by running data migrations.
def do_up(c):
    # Optimization note:
    # Goose is much much faster to run then a PSQL command. Instead of ensuring the db exists
    # before applying migrations, simply try the migrations first. If they fail, fall back to
    # running PSQL db to ensure the db exists and try again.
    try:
        goose()

    except subprocess.CalledProcessError:
        if MODE == CHANGE:
            recreate_db_user(c)

        cmd = "CREATE DATABASE %s WITH OWNER = %s;" % (DB_NAME, DB_USER)
        if MODE == CHANGE:
            success = run_psql_cmd(c, cmd, POSTGRES_DB, ADMIN_DB_USER, ADMIN_DB_PASS)
        else:
            success = run_psql_cmd(c, cmd, MAIN_DB, DB_USER, DB_PASS)
        if not success:
            # if the db exists, it's totally ok too
            pass

        cmd = "CREATE EXTENSION IF NOT EXISTS pgcrypto;"
        if not run_psql_cmd(c, cmd, DB_NAME, DB_USER, DB_PASS):
            # if the extension exists, it's totally ok too
            pass

        goose()


def recreate_db_user(c):
    cmd = "DROP ROLE IF EXISTS %s;" % DB_USER
    if not run_psql_cmd(c, cmd, POSTGRES_DB, ADMIN_DB_USER, ADMIN_DB_PASS):
        # if the user not exists, it's totally ok
        pass

    if LOCATION == LOCAL:
        cmd = "CREATE ROLE %s WITH SUPERUSER CREATEDB LOGIN ENCRYPTED PASSWORD '%s';" % (DB_USER, DB_PASS)
    else:
        cmd = "CREATE ROLE %s WITH CREATEDB LOGIN ENCRYPTED PASSWORD '%s';" % (DB_USER, DB_PASS)
    if not run_psql_cmd(c, cmd, POSTGRES_DB, ADMIN_DB_USER, ADMIN_DB_PASS):
        # if the user exists, it's totally ok
        pass

    if not run_psql_cmd(c, "GRANT %s TO %s;" % (DB_USER, ADMIN_DB_USER), POSTGRES_DB, ADMIN_DB_USER, ADMIN_DB_PASS):
        # if the privileges are granted, it's totally ok too
        pass

    if LOCATION != LOCAL:
        if not run_psql_cmd(c, "GRANT rds_superuser TO %s;" % DB_USER, POSTGRES_DB, ADMIN_DB_USER, ADMIN_DB_PASS):
            # if the privileges are granted, it's totally ok too
            pass


# Drops the db (we never want to go down a single data migration layer,
# we just want to start from nothing).
def drop(c):
    if DEBUG:
        print "Dropping " + DB_NAME + " DB..."

    if MODE == CHANGE:
        db = POSTGRES_DB
        user = ADMIN_DB_USER
        password = ADMIN_DB_PASS
    else:
        db = MAIN_DB
        user = DB_USER
        password = DB_PASS

    if not db_exists(c, user, password):
        return

    cmd = "REVOKE CONNECT ON DATABASE %s FROM public;" % DB_NAME
    if not run_psql_cmd(c, cmd, db, user, password):
        raise ValueError("Couldn't connect to psql server!")

    cmd = "SELECT pid, pg_terminate_backend(pid) FROM pg_stat_activity " + \
          "WHERE datname = current_database() AND pid <> pg_backend_pid();"
    if not run_psql_cmd(c, cmd, db, user, password):
        raise ValueError("Couldn't connect to psql server!")

    cmd = "DROP DATABASE IF EXISTS %s;" % DB_NAME
    if not run_psql_cmd(c, cmd, db, user, password):
        raise ValueError("Couldn't connect to psql server!")


def db_exists(c, user, password):
    if DEBUG:
        print "Checking if DB " + DB_NAME + " exists"
    return run_psql_cmd(c, ';', DB_NAME, user, password)


def export_host_addr():
    if DEBUG:
        print "Exporting host address..."
    print "PSQL host: " + DB_HOST
    print "PSQL port: " + DB_PORT


# Print the mysql host address to stdout.
def print_host(c):
    if not status(c):
        raise ValueError("No PSQL instance found")
    export_host_addr()


# Starts the PSQL service. If it's already running, do nothing.
def start(c):
    if DEBUG:
        print "Starting the PSQL service..."
    needs_start = (LOCATION == LOCAL) and not status(c)

    if needs_start:
        # try to bring up the psql client container
        try_pull(PSQL_CONTAINER_IMAGE, tag=DOCKER_TAG)

        try:
            if DEBUG:
                print "Creating network..."
            ipam_pool = docker.types.IPAMPool(subnet='172.8.0.0/16')
            ipam_config = docker.types.IPAMConfig(pool_configs=[ipam_pool])
            c.create_network('oidcnet', driver='bridge', ipam=ipam_config)
        except APIError as err:
            print >> sys.stderr, "If the following line says that a pool overlaps with something, "\
                                 " it means that the network already exists, this is success."
            print >> sys.stderr, err
            # if exception is thrown, that just means the container is already created.
            pass

        try:
            if DEBUG:
                print "Creating container %s..." % DB_CONTAINER
            c.create_container(image=PSQL_CONTAINER_IMAGE + ":" + DOCKER_TAG,
                               name=DB_CONTAINER,
                               ports=[5432],
                               detach=True,
                               host_config=c.create_host_config(
                                   restart_policy={"Name": "always"},
                                   binds={
                                       DATA_DIR: {
                                           'bind': '/var/lib/postgresql/data',
                                           'mode': 'rw',
                                       }
                                   }),
                               networking_config=c.create_networking_config({
                                   'oidcnet': c.create_endpoint_config(ipv4_address='172.8.0.8')
                               }),
                               environment={"LC_ALL": "C.UTF-8"})
        except APIError as err:
            print >> sys.stderr, "If the following line says that the name " + DB_CONTAINER + \
                                 " already exists, this is success."
            print >> sys.stderr, err
            # if exception is thrown, that just means the container is already created.
            pass

        # Then start the container
        if DEBUG:
            print "Starting container %s..." % DB_CONTAINER
        c.start(container=DB_CONTAINER)

        export_host_addr()

        # Wait for the PSQL daemon to be running
        for _ in range(RETRIES):
            if run_psql_cmd(c, ";", POSTGRES_DB, LOCAL_ADMIN_USER, LOCAL_ADMIN_PASS):
                break
            time.sleep(2)
        else:
            raise ValueError("Couldn't connect to " + DB_CONTAINER + "!")
    else:
        # it's already running, just be sure we know how to find it.
        if DEBUG:
            print "PSQL service is already started"
        export_host_addr()


# Stops PSQL service
def stop(c):
    if DEBUG:
        print "Stopping PSQL docker container..."
    if LOCATION != LOCAL:
        print "Cannot stop nonlocal PSQL service"
    else:
        try:
            c.stop(DB_CONTAINER)
        except APIError as err:
            print >> sys.stderr, err
            pass


# Burn and Kill the PSQL service without hesitation.
def destroy(c):
    if DEBUG:
        print "Destroying PSQL docker container..."
    if LOCATION != LOCAL:
        print "Cannot destroy nonlocal PSQL service"
    else:
        try:
            c.kill(DB_CONTAINER)
            c.remove_container(DB_CONTAINER)
        except APIError as err:
            print >> sys.stderr, err
            pass


# Return True iff the service is running.
def status(c):
    # If env var set, we require the service to be running there.
    if DEBUG:
        print "Checking status..."
    if LOCATION != LOCAL:
        if run_psql_cmd(c, ";", DB_NAME, DB_USER, DB_PASS):
            if DEBUG:
                print "Remote PSQL at " + DB_HOST + " is running!"
            return True
        else:
            if DEBUG:
                print "Remote PSQL at " + DB_HOST + " didn't respond!"
            return False
    else:
        try:
            s = c.inspect_container(DB_CONTAINER)
        except APIError:
            if DEBUG:
                print "PSQL service container " + DB_CONTAINER + " needs to be created"
            return False
        else:
            if s["State"]["Running"]:
                if DEBUG:
                    print "PSQL service container " + DB_CONTAINER + " is running"
                return True
            else:
                if DEBUG:
                    print "PSQL service container " + DB_CONTAINER + " is stopped"
                return False


# Try to pull the specified image:tag, but don't throw if we fail.  This provides
# some robustness if the registry is offline: the tagged image we want may already
# be cached locally.  If so, we win; if not we fall over later at container run anyway.
# Normally we'client just use wrap docker.Client.pull, however that doesn't work with a private
# docker registry.  It fails with an "unauthenticated" error even if docker is already
# logged in.  Instead, we call out to the official binary which seems to work fine.
#
# Note that we only ever want to try pulling the container once per execution,
# to ensure that we have a mysql image.  However, subsequent calls do nothing,
# which prevents us from redundantly pulling the same image.
HAS_PULLED = False


def try_pull(image, tag):
    global HAS_PULLED
    if HAS_PULLED:
        return
    try:
        if DEBUG:
            print "Pulling down PSQL image %s:%s" % (image, tag)
        print subprocess.check_output(["docker", "pull", image + ":" + tag], stderr=subprocess.STDOUT)
        HAS_PULLED = True
    except Exception as err:
        print >> sys.stderr, err
        pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Manage docker containers for OIDC services')
    parser.add_argument('location', default=LOCAL, nargs="?",
                        choices=[STAGING, PRODUCTION, LOCAL],
                        help="The DB Location")
    parser.add_argument('mode', default=TEST, nargs="?",
                        choices=[TEST, CHANGE],
                        help="The work mode")
    parser.add_argument('action', default='status', nargs="?",
                        choices=[START, STOP, RESTART, DROP, REINSTALL, DESTROY, STATUS, HOST],
                        help='The action to perform')
    parser.add_argument('--rootdir', default=os.getcwd(), help="Root of auth-server directory (defaults to cwd)")
    parser.add_argument('--datadir', default=os.path.join(os.getcwd(), 'local-db', 'postgres'),
                        help="Local DB data directory (defaults to cwd/local-db/postgres)")
    parser.add_argument('--debug', action="store_true", help="Turn on debugging output")
    parser.add_argument('--password', default='', help="DB password")
    parser.add_argument('--admin-password', default='', help="Admin DB password")
    args = parser.parse_args()

    DB_PASS = args.password
    ADMIN_DB_PASS = args.admin_password

    LOCATION = args.location
    if LOCATION == STAGING:
        DB_HOST = STAGING_HOST
        DB_PORT = STAGING_PORT
        ADMIN_DB_USER = REMOTE_ADMIN_USER
    elif LOCATION == PRODUCTION:
        DB_HOST = PRODUCTION_HOST
        DB_PORT = PRODUCTION_PORT
        ADMIN_DB_USER = REMOTE_ADMIN_USER
    else:
        DB_HOST = LOCAL_HOST
        DB_PORT = LOCAL_PORT
        DB_PASS = LOCAL_CHANGE_PASS
        ADMIN_DB_USER = LOCAL_ADMIN_USER
        ADMIN_DB_PASS = LOCAL_ADMIN_PASS

    MODE = args.mode
    if MODE == CHANGE:
        DB_NAME = MAIN_DB
    else:
        DB_NAME = TEST_DB

    ACTION = args.action
    ROOT_DIR = args.rootdir
    DEBUG = args.debug

    if args.datadir != os.path.join(os.getcwd(), 'local-db', 'postgres'):
        args.datadir = os.path.join(ROOT_DIR, 'local-db', 'postgres')
    DATA_DIR = args.datadir

    SECRETS_DIR = os.path.join(ROOT_DIR, 'secrets')

    # Create docker client
    if os.getenv("DOCKER_HOST"):
        kwargs = kwargs_from_env()
        client = docker.APIClient(**kwargs)
    else:
        client = docker.APIClient()

    if ACTION == START:
        start(client)
        do_up(client)
        status(client)
    elif ACTION == STOP:
        stop(client)
        status(client)
    elif ACTION == RESTART:
        stop(client)
        start(client)
        do_up(client)
        status(client)
    elif ACTION == DROP:
        start(client)
        drop(client)
        status(client)
    elif ACTION == REINSTALL:
        drop(client)
        do_up(client)
        status(client)
    elif ACTION == DESTROY:
        destroy(client)
    elif ACTION == HOST:
        print_host(client)
    else:
        status(client)
