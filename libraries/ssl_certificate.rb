#
# Author:: Thijs Houtenbos <thoutenbos@schubergphilis.com>
# Cookbook:: acme
# Provider:: certificate
#
# Copyright 2015-2016 Schuberg Philis
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#


class Chef
  class Provider
    class SSLCertificate < Chef::Provider::LWRPBase

      use_inline_resources

      def whyrun_supported?
        true
      end

      def load_current_resource
      end

      def check_expiry
        return false if @current_cert.nil?
        @current_cert.not_after >= new_resource.min_expiry
      end

      def check_alt_names
        return false if @current_cert.nil?

        extensions = @current_cert.extensions || []
        alt_extension = extensions.find { |x| x.oid == 'subjectAltName' }

        current_alt_names = []

        if !!alt_extension
          data = OpenSSL::ASN1.decode(alt_extension).value[1].value
          current_alt_names = OpenSSL::ASN1.decode(data).map { |x| x.value }
        end

        #We ignore if the cn is among the subjectAltNames in one or the other certificate.
        current_cn = @current_cert.subject.to_a.map { |x| x[1] if x[0] == 'CN' }

        (current_alt_names | [current_cn]).flatten.compact.sort.uniq == (new_resource.alt_names | [new_resource.cn]).flatten.compact.sort.uniq
      end

      def check_cn
        return false if @current_cert.nil?

        @current_cert.subject.to_a.map { |x| x[1] if x[0] == 'CN' }.compact.include?(new_resource.cn)
      end

      def check_pkey
        return false if @current_cert.nil?

        @current_cert.check_private_key(@current_key)
      end

      def check_issuer
        return false if @current_cert.nil?

        extensions = @current_cert.extensions || []
        authority_extension = extensions.find { |x| x.oid == 'authorityInfoAccess' }

        if !!authority_extension
          data = OpenSSL::ASN1.decode(authority_extension).value[1].value
          issuer = OpenSSL::ASN1.decode(data).value[1].value[1].value

          issuer == node['acme']['issuer']
        else
          false
        end
      end

      def action_create
        key = acme_ssl_key new_resource.key do
          action :nothing
        end

        key.run_action(:create_if_missing)

        @current_key = key.load

        if ::File.exist?(@new_resource.path)
          @current_cert = ::OpenSSL::X509::Certificate.new ::File.read new_resource.path
        end

        unless (!@current_cert.nil? && check_expiry && check_cn && check_alt_names && check_pkey && check_issuer)
          ::Chef::Log.info("Renewing ACME certificate for #{@new_resource.cn}: expiry = #{check_expiry}, cn = #{check_cn}, alt_name = #{check_alt_names}, pkey = #{check_pkey} issuer=#{check_issuer}")

          converge_by("Renew ACME certifiacte") do
            domains = [new_resource.cn, new_resource.alt_names].flatten.compact.uniq

            order = acme_client.new_order(identifiers: domains)

            pending_authorizations = order.authorizations.select { |a| a.status == 'pending' }

            pending_authorizations.each do |a|
              ::Chef::Log.info("Authorization #{a.to_h} pending")

              compile_and_converge_action { setup_challenge(a) }

              ::Chef::Log.info("Requesting verification...")
              validate_challenge(a)
            end

            times = 60
            while pending_authorizations.any? { |a| a.status == 'pending' } && times > 0
              sleep 1
              times -= 1

              still_pending = pending_authorizations.select { |a| a.status == 'pending' }
              ::Chef::Log.info("Waiting for verification for #{still_pending.count} challenges...")
              still_pending.each(&:reload)
            end

            ::Chef::Log.info("Tearing down verification...")

            pending_authorizations.each { |c| compile_and_converge_action { teardown_challenge(c) } }


            failed_authorizations = pending_authorizations.reject { |a| a.status == 'valid' }
            fail "Validation failed for some domains: #{failed_authorizations.map {|a| a.to_h }}" unless failed_authorizations.empty?

            begin
              csr = acme_csr(new_resource.cn, @current_key, new_resource.alt_names)
              order.finalize(csr: csr)

              times = 60
              while order.status == 'processing' && times > 0
                ::Chef::Log.info("Waiting for completion of certificate order...")

                sleep 1
                times -= 1
                order.reload
              end

              fail "Processing order timed out: #{order.status}" unless order.status == 'valid'
            rescue Acme::Client::Error => e
              fail "[#{new_resource.cn}] Certificate request failed: #{e.message}"
            else

              file new_resource.path do
                content order.certificate

                owner new_resource.owner
                group new_resource.group
                mode 00644
              end.run_action(:create)
            end
          end
        end
      end
    end
  end
end

