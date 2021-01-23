require 'chef/version_constraint'

class Chef
  class Provider
    class SSLCertificate
      class DigitalOceanDns < ::Chef::Provider::SSLCertificate

        attr_reader :client

        def initialize(*args)
          super(*args)

          require 'droplet_kit'

          @client = DropletKit::Client.new(access_token: node['digitalocean']['token'])
          @records = {}
        end

        def setup_challenge(authorization)
          challenge = authorization.dns
          fqdn = [challenge.record_name, authorization.domain].join('.')

          domain = fqdn.split('.')[-2..-1].join('.')
          record_name = fqdn.split('.')[0...-2].join('.')

          record = DropletKit::DomainRecord.new(
            type: challenge.record_type,
            name: record_name,
            data: challenge.record_content,
            ttl: 30
          )

          Chef::Log.info("Creating challenge DNS record for domain #{domain}: #{record.to_h.inspect}")

          r = client.domain_records.create(record, for_domain: domain)

          @records[authorization] = { for_domain: domain, id: r.id }
        end

        def validate_challenge(authorization)
          authorization.dns.request_validation
        end

        def teardown_challenge(authorization)
          Chef::Log.info("Tearing down challenge DNS record: #{@records[authorization].inspect}")


          client.domain_records.delete(@records.delete(authorization))
        end
      end
    end
  end
end
