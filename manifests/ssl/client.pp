# Creates an SSL client keystore which can be used by applications wanting to
# authenticate to this Kafka cluster.
#
# Note: As we are generating the client certs on the Kafka nodes themselves,
# we will end up with certs being created on each server. This isn't a big
# issue, since we validate by the CA, not by the individual cert fingerprint,
# but if it bothers you, you'd need to mount ${ssl_dir} as shared storage
# amongst the cluster members.

define kafka::ssl::client (
  $ensure                 = 'present',
  $client_name            = $name,
  $ssl_dir                = $::kafka::ssl::broker::ssl_dir,
  $ssl_validity_days      = $::kafka::ssl::broker::ssl_validity_days,
  $ssl_keystore_password  = $::kafka::ssl::broker::ssl_keystore_password,
  $group                  = $::kafka::ssl::broker::group,
  $user                   = $::kafka::ssl::broker::user,
  ) {

  # Ensure that SSL is fully setup on the broker
  require ::kafka::ssl::broker

  # Set some sensible defaults in this definition
  File {
    owner   => $user,
    group   => $group,
  }

  Exec {
    path => '/bin:/sbin:/usr/bin:/usr/sbin',
    cwd  => $ssl_dir,
  }

  # Currently there is no way to revoke a certificate which is pretty silly.
  # Let's at least make it clear to the admin that this is a problem... longer
  # term solution is probably to blacklist disabled clients by creating a deny
  # all ACL for the user.
  if ($ensure != 'absent') {
    notify { "Unable to remove client ${client_name} - Kafka does not support Certicate Revocation Lists (CRLS). To revoke, roll a new CA cert and key and regenerate all clients.": }
  }


  # Generate a cert and key in Java keystore for the client
  exec { "client_keystore_${client_name}":
    command => "keytool -keystore ${ssl_dir}/client-${client_name}.keystore.jks -storepass ${ssl_keystore_password} -keypass ${ssl_keystore_password} -genkey -dname \"CN=${client_name}, OU=Kafka, O=Kafka, L=Kafka, S=Kafka, C=US\" -alias localhost -validity ${ssl_validity_days}",
    creates => "${ssl_dir}/client-${client_name}.keystore.jks",
  } ->

  # Get the CSR out of the keystore, so we can sign it and then import the signed
  # certificate and the CA cert into the keystore.
  exec { "client_keystore_get_csr_${client_name}":
    command => "keytool -keystore ${ssl_dir}/client-${client_name}.keystore.jks -storepass ${ssl_keystore_password} -keypass ${ssl_keystore_password} -certreq -alias localhost -file ${ssl_dir}/client-${client_name}.csr",
    creates => "${ssl_dir}/client-${client_name}.csr",
  } ->

  exec { "client_keystore_sign_cert_${client_name}":
    command => "openssl x509 -req -CA ${ssl_dir}/ca.cert  -CAkey ${ssl_dir}/ca.key -in ${ssl_dir}/client-${client_name}.csr -out ${ssl_dir}/client-${client_name}.signed.crt -days ${ssl_validity_days} -CAcreateserial",
    creates => "${ssl_dir}/client-${client_name}.signed.crt",
  }


  # If a new client keystore is created, import the CA cert into it.
  exec { "client_keystore_import_ca_cert_${client_name}":
    command     => "keytool -keystore ${ssl_dir}/client-${client_name}.keystore.jks -storepass ${ssl_keystore_password} -keypass ${ssl_keystore_password} -alias CARoot -import -file ${ssl_dir}/ca.cert -noprompt",
    subscribe   => Exec["client_keystore"],
    refreshonly => true,
  }

  # Once the client cert has been signed, import the signed cert into the Java keystore.
  exec { "client_keystore_import_signed_cert_${client_name}":
    command     => "keytool -keystore ${ssl_dir}/client-${client_name}.keystore.jks -storepass ${ssl_keystore_password} -keypass ${ssl_keystore_password} -alias localhost -import -file ${ssl_dir}/client-${client_name}.signed.crt -noprompt",
    subscribe   => Exec['client_keystore_sign_cert'],
    refreshonly => true,

    # Import fails if we haven't already imported the CA cert.
    require     => Exec['client_keystore_import_ca_cert'],
  }

  # TODO: Export out in p12 and PEM formats to make it easier to use with
  # other apps.


}
