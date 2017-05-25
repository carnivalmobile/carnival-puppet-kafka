# Creates an SSL client keystore which can be used by applications wanting to
# authenticate to this Kafka cluster.
#
# Note: As we are generating the client certs on the Kafka nodes themselves,
# we will end up with certs being created on each server. This isn't a big
# issue, since we validate by the CA, not by the individual cert fingerprint,
# but if it bothers you, you'd need to mount ${ssl_dir} as shared storage
# amongst the cluster members.
#
# Note: To make SSL authentication actually work, make sure you add the
# following param to Hiera:
#
#   kafka::broker::config:
#     ssl.client.auth: required
#

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
    cwd  => "$ssl_dir/clients/",
  }

  # Currently there is no way to revoke a certificate which is pretty silly.
  # Let's at least make it clear to the admin that this is a problem... longer
  # term solution is probably to blacklist disabled clients by creating a deny
  # all ACL for the user.
  if ($ensure == 'absent') {
    notify { "Unable to remove client ${client_name} - Kafka does not support Certicate Revocation Lists (CRLS). To revoke, roll a new CA cert and key and regenerate all clients.": }
  }


  # Generate a cert and key in Java keystore for the client
  exec { "client_keystore_${client_name}":
    command => "keytool -keystore ${ssl_dir}/clients/${client_name}.keystore.jks -storepass ${ssl_keystore_password} -keypass ${ssl_keystore_password} -genkey -dname \"CN=${client_name}, OU=Kafka, O=Kafka, L=Kafka, S=Kafka, C=US\" -alias localhost -validity ${ssl_validity_days}",
    creates => "${ssl_dir}/clients/${client_name}.keystore.jks",
  } ->

  # Get the CSR out of the keystore, so we can sign it and then import the signed
  # certificate and the CA cert into the keystore.
  exec { "client_keystore_get_csr_${client_name}":
    command => "keytool -keystore ${ssl_dir}/clients/${client_name}.keystore.jks -storepass ${ssl_keystore_password} -keypass ${ssl_keystore_password} -certreq -alias localhost -file ${ssl_dir}/clients/${client_name}.csr",
    creates => "${ssl_dir}/clients/${client_name}.csr",
  } ->

  exec { "client_keystore_sign_cert_${client_name}":
    command => "openssl x509 -req -CA ${ssl_dir}/ca.crt  -CAkey ${ssl_dir}/ca.key -in ${ssl_dir}/clients/${client_name}.csr -out ${ssl_dir}/clients/${client_name}.crt -days ${ssl_validity_days} -CAcreateserial",
    creates => "${ssl_dir}/clients/${client_name}.crt",
  }


  # If a new client keystore is created, import the CA cert into it.
  exec { "client_keystore_import_ca_cert_${client_name}":
    command     => "keytool -keystore ${ssl_dir}/clients/${client_name}.keystore.jks -storepass ${ssl_keystore_password} -keypass ${ssl_keystore_password} -alias CARoot -import -file ${ssl_dir}/ca.crt -noprompt",
    subscribe   => Exec["client_keystore_${client_name}"],
    refreshonly => true,
  }

  # Once the client cert has been signed, import the signed cert into the Java keystore.
  exec { "client_keystore_import_signed_cert_${client_name}":
    command     => "keytool -keystore ${ssl_dir}/clients/${client_name}.keystore.jks -storepass ${ssl_keystore_password} -keypass ${ssl_keystore_password} -alias localhost -import -file ${ssl_dir}/clients/${client_name}.crt -noprompt",
    subscribe   => Exec["client_keystore_sign_cert_${client_name}"],
    refreshonly => true,

    # Import fails if we haven't already imported the CA cert.
    require     => Exec["client_keystore_import_ca_cert_${client_name}"],
  }


  # Get PKCS12 (.pk12) version of the keystore (cert + key)
  exec { "client_keystore_export_pkcs12_${client_name}":
    command     => "keytool -importkeystore -srckeystore ${ssl_dir}/clients/${client_name}.keystore.jks -srcstorepass ${ssl_keystore_password} -srckeypass ${ssl_keystore_password} -destkeystore ${ssl_dir}/clients/${client_name}.p12 -deststoretype PKCS12 -srcalias localhost -deststorepass ${ssl_keystore_password} -destkeypass ${ssl_keystore_password}",
    creates     => "${ssl_dir}/clients/${client_name}.p12",
    require     => Exec["client_keystore_import_signed_cert_${client_name}"],
  }

  # Get the PEM version of the client key (we pull this from the pkcs12 file)
  exec { "client_keystore_export_key_pem_${client_name}":
    command     => "openssl pkcs12 -in ${ssl_dir}/clients/${client_name}.p12 -nodes -nocerts -password \"pass:${ssl_keystore_password}\" -out ${ssl_dir}/clients/${client_name}.key",
    creates     => "${ssl_dir}/clients/${client_name}.key",
    require     => Exec["client_keystore_export_pkcs12_${client_name}"],
  }


  # Create distribution archive of all the certs for a given client.
  exec { "client_dist_archive_${client_name}":
    command     => "tar --transform 's,^,kafka-creds-${client_name}/,' -cjf ${ssl_dir}/dist/kafka-creds-${client_name}.tar.bz2 ${client_name}.* ../ca.crt",
    creates     => "${ssl_dir}/dist/kafka-creds-${client_name}.tar.bz2",
    require     => [
      # Make sure we've finished generating everything.
      Exec["client_keystore_export_key_pem_${client_name}"],
      Exec["client_keystore_export_pkcs12_${client_name}"],
      Exec["client_keystore_import_signed_cert_${client_name}"],
    ]
  }

}
