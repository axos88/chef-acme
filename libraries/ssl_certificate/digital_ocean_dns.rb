require 'chef/version_constraint'

class Chef
  class Provider
    class SSLCertificate
      class DigitalOceanDns < ::Chef::Provider::SSLCertificate

        attr_reader :client

        def initialize(*args)
          super(*args)

          require 'droplet_kit'

          token = Chef::EncryptedDataBagItem.load("encrypted", "digitalocean_token")['data']

          @client = DropletKit::Client.new(access_token: token)
          @records = {}
        end

        def setup_challenge(authorization)
          challenge = authorization.dns
          fqdn = [challenge.record_name, authorization.domain].join('.')

          domain = fqdn.split('.')[-2..-1].join('.')
          record_name = fqdn.split('.')[0...-2].join('.')

          all_records = client.domain_records.all(for_domain: domain)
          matching_records = all_records.select { |r| r['name'] == record_name && r['type'] == challenge.record_type }

          matching_records.each do |r|
            Chef::Log.info("Deleting challenge DNS record for domain #{domain} #{r.to_h}")
            client.domain_records.delete(for_domain: domain, id: r.id)
          end

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

        private def txt_records(ns, fqdn)
          resolver = Resolv::DNS.new(nameserver: ns)
          resolver.timeouts = 2
          resolver.getresources(fqdn, Resolv::DNS::Resource::IN::TXT).map(&:strings).flatten
        end

        private def validate_ns_records(ns, fqdn, value)
            records = txt_records(ns, fqdn)
            raise "#{fqdn} TXT records on #{ns} do not contain #{value}, only #{records}" unless records.find { |r| r == value }
        end

        def validate_challenge(authorization)
          challenge = authorization.dns
          fqdn = [challenge.record_name, authorization.domain].join('.')
          value = challenge.record_content


          dns_servers_pending_propagation = node['acme']['dns_servers'].map { |s| [ "#{s['provider']} - #{s['location']}", s['address']] }

          begin
            retry_times("Waiting for DNS propagation...", 60) do
              until dns_servers_pending_propagation.empty? do
                nm, address = dns_servers_pending_propagation.first
                Chef::Log.debug("Checking DNS propagation to #{nm} at #{address}")
                validate_ns_records(address, fqdn, value)
                Chef::Log.info("DNS propagation to #{nm} at #{address} successful")
                dns_servers_pending_propagation.shift
              end
            end
          rescue => e
            Chef::Log.warn("#{e.message} Trying validation anyway.")
          end

          challenge.request_validation
        end

        def teardown_challenge(authorization)
          Chef::Log.info("Tearing down challenge DNS record: #{@records[authorization].inspect}")
          client.domain_records.delete(@records.delete(authorization))
        end
      end
    end
  end
end
