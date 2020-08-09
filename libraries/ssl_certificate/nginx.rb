require 'chef/version_constraint'

class Chef
  class Provider
    class SSLCertificate
      class Nginx < ::Chef::Provider::SSLCertificate

        def validation_method
          :http
        end

        def basedir
          '/var/www/acme'
        end

        def initialize(*args)
          super(*args)

          if node.automatic_attrs[:nginx][:version].is_a?(String)
            unless Chef::VersionConstraint.new(">= 1.10").include?(node.automatic_attrs[:nginx][:version])
              Chef::Log.warn("This provider has not been tested with nginx < 1.10")
            end
          end
        end

        attr_reader :nginx

        def setup_challanges(http_challange)
          directory ::File.dirname(::File.join(basedir, http_challange.filename)) do
            owner     node[:nginx][:user]
            group     node[:nginx][:user]
            mode      00755
            recursive true
          end

          file ::File.join(basedir, http_challange.filename) do
            content http_challange.file_content

            mode 00644
            owner node[:nginx][:user]
          end
        end

        def teardown_challanges(http_challange)
          file ::File.join(basedir, http_challange.filename) do
            action :delete
          end
        end
      end
    end
  end
end
