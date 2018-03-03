# frozen_string_literal: true

module Xml
  module Kit
    class Template
      TEMPLATES_DIR = Pathname.new(File.join(__dir__, 'templates/'))

      attr_reader :target

      def initialize(target)
        @target = target
      end

      # Returns the compiled template as a [String].
      #
      # @param options [Hash] The options hash to pass to the template engine.
      def to_xml(options = {})
        template.render(target, options)
      end

      private

      def template_path
        return target.template_path if target.respond_to?(:template_path)
        TEMPLATES_DIR.join(template_name)
      end

      def template_name
        "#{target.class.name.split('::').last.underscore}.builder"
      end

      def template
        @template ||= Tilt.new(template_path.to_s)
      end
    end
  end
end
