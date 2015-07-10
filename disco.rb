#!/usr/bin/env ruby

MAX_BODY_LENGTH = 4_096


%w| pathname net/http json erb optparse yaml|.map(&method(:require))

Binding.send(:alias_method, :get, :local_variable_get)
Encoding.default_internal = "utf-8"
Encoding.default_external = "utf-8"

module Disco

  class Request
    def initialize(base_url:, port: 80)
      @base_url = base_url
      @port = port
    end

    def do_request(method: :get, base_url: @base_url, port: @port, path: "/",
                   headers: {}, params: {}, payload: "")
      uri = URI("#{base_url}:#{@port}")
      http = Net::HTTP.new(uri.host, uri.port)

      query = normalize_params(params)
      path = "#{path}?#{query}" if query and not query.empty?
      timestamp = Time.now

      result = case method.to_sym
               when :get
                 http.get(path, headers)
               when :post
                 http.post(path, payload, headers)
               when :patch
                 http.post(path, payload, headers)
               when :put
                 http.put(path, payload, headers)
               when :delete
                 http.delete(path, headers)
               when :head
                 http.head(path, headers)
               when :options
                 http.options(path, headers)
               else
                 raise ArgumentError.new "Unknown method: '#{method}'"
               end

      response_time      = Time.now - timestamp
      headers            = deflate_headers(result.to_hash)
      type, decoded_body = decode_body((result.body || '').force_encoding("utf-8"),
                                       headers["content-type"])

      {
        "path"           => path,
        "headers"        => headers,
        "code"           => result.code.to_i,
        "message"        => result.message,
        "type"           => type,
        "body"           => decoded_body || "..empty..",
        "content_length" => result.content_length,
        "http_version"   => result.http_version,
        "response_time"  => response_time
      }
    end

    private
    def deflate_headers(hsh)
      hsh.each do |k,v|
        next if v.size > 1
        hsh[k] = v.first
      end
    end

    def decode_body(body, type = "text")
      return nil if body.nil?
      return ""  if body.strip.empty?
      return nil if body == "null"

      case type
      when /json/
        require 'json'
        [:json, JSON.load(body, nil)]
      when /xml/
        require 'rexml/document'
        xml = REXML::Document.new(body)
        formatter = REXML::Formatters::Pretty.new
        formatter.compact = true
        result = ""
        result << formatter.write(xml.root,"")
        [:xml, result]
      when /csv/
        require 'csv'
        [:csv, CSV.parse(body)]
      when /html/
        [:html, body]
      else
        [:text, body]
      end
    end

    def normalize_params(params)
      case params
      when String
        params.strip
      when Hash, Array
        URI.encode_www_form(params)
      else
        nil
      end
    end
  end

  module Formater extend self
    module Helpers; end

    class Markamini
      attr_accessor :node
      include Disco::Formater::Helpers

      def self.document(&block)
        self.send :undef_method, :p
        new.instance_eval(&block).to_s
      end

      def method_missing(name, opts = {}, &block)
        parent = @node
        @node = Node.new(parent, name, opts)
        parent.children << @node if parent
        if block_given?
          val = instance_eval(&block)
          if val.is_a?(String)
            @node.children << val
            @node.plain = true
          end
        end
        parent ? @node = parent : @node
      end

      class Node
        attr_accessor :name, :options, :children, :parent, :plain

        def initialize(parent, name, options = {})
          @options = options
          @name = name
          @parent = parent
          @children = []
          @level = 0
          pr = parent
          while(pr)
            @level += 1
            pr.parent ? pr = pr.parent : break
          end
          if options.is_a?(String)
            @options = nil
            @children = [options]
            @plain = true
          end
        end

        def to_s
          if children.any?
            "#{get_space}<#{name}#{' ' + attrs unless attrs.empty?}>\n#{get_children}#{get_space}</#{name}>\n"
          else
            "#{get_space}<#{name} #{' ' + attrs unless attrs.empty?}></#{name}>\n"
          end
        end

        def get_children
          if @plain
            get_space(1) + children.join + "\n"
          else
            children.join
          end
        end

        def get_space(n=0)
          "  " * (@level + n)
        end

        def attrs
          return "" if options.nil?
          options.map {|k, v| "#{k}=#{v.inspect}" }.join(" ")
        end
      end

    end

    def format_and_save_output
      Dir.mkdir(dirname) unless Dir.exist?(dirname)
      case File.extname(filename)
      when ".html" then output_html()
      when "json"  then output_json()
      else
        raise "Unknown format for output: #{filename}"
      end
    end

    def output_html
      html = Markamini.document do
        html do

          head do
            title  "API Disco!"
            meta   "http-equiv"=>"Content-Type", "content"=>"text/html; charset=utf-8"
            link   rel: "stylesheet", href: "https://maxcdn.bootstrapcdn.com/bootstrap/3.3.4/css/bootstrap.min.css"
            link   rel: "stylesheet", href: "https://maxcdn.bootstrapcdn.com/bootstrap/3.3.4/css/bootstrap-theme.min.css"
            script src: "https://ajax.googleapis.com/ajax/libs/jquery/1.11.2/jquery.min.js"
            script src: "https://maxcdn.bootstrapcdn.com/bootstrap/3.3.4/js/bootstrap.min.js"
            link   rel: "stylesheet", href: "https://cdnjs.cloudflare.com/ajax/libs/highlight.js/8.6/styles/default.min.css"
            script src: "https://cdnjs.cloudflare.com/ajax/libs/highlight.js/8.6/highlight.min.js"
            style do <<__
              .panel-heading:hover{cursor: pointer};
              span.bordered{border: 1px solid #ddd; padding: 4px 8px};
__
            end
          end

          body do
            div class: "container" do
              div class: "row" do
                div class: "col-md-12" do
                  h1(class: "text-center") { CF.recipe["title"] }
                  h3(class: "text-center") { CF.recipe["subtitle"] } if CF.recipe["subtitle"]
                  div class: "panel panel-default" do
                    div class: "panel-body" do
                      p(class: "lead") { CF.recipe["description"] }
                    end
                  end
                  # Endpoints
                  CF.recipe["endpoints"].each do |url, val|
                    div class: "panel panel-default" do
                      id = "entry_#{Digest::MD5.hexdigest(val['path'])}"
                      div class: "panel-heading", id: id  do
                        h3(class: "panel-title") do
                          a href: "##{id}", class: "text-right" do
                            val["path"]
                          end
                        end
                      end

                      div class: "panel-body" do
                        p(class: "lead"){ val["description"] }
                        hr
                        p { val["params"] }
                        hr

                        val["methods"].each do |meth, examples|
                          h5 "#{meth.upcase} #{val['path']}"

                          examples.each do |ex|
                            if CF.recipe["only_exclusive_examples"]
                              next if not ex.has_key?("only")
                            end

                            if ex.has_key?("skip")
                              div class: "panel panel-info col-md-offset-1" do
                                div class: "panel-heading" do
                                  "Example skipped!"
                                end
                              end
                              next
                            end

                            case ex["result"]
                            when Hash then render_example(binding)
                            else
                              div class: "panel panel-danger col-md-offset-1" do
                                div class: "panel-heading" do
                                  "Error! #{ex['result'].message}"
                                end
                              end
                            end
                          end

                        end

                      end
                    end
                  end
                end
              end
            end
            footer do
              hr
              p(class: "text-center") { CF.recipe["footer"] }
            end
            script do
              <<__
              $(document).ready(function() {
                 $('td.result').each(function(i, block) {
                   hljs.highlightBlock(block);
                 });
              });
__
            end
          end

        end
      end

      File.open(fullname, "wb"){|f| f << html.to_s}
    end

    module Helpers
      def h(text)
        ::CGI::escapeHTML(text || "")
      end

      def hl(style)
        case style
        when :text then "ini"
        when :csv  then "js"
        else
          style
        end
      end

      def response_code_to_color(code)
        case code.to_i
        when 100..199 then "primary"
        when 200..299 then "success"
        when 300..399 then "info"
        when 400..499 then "warning"
        when 500..599 then "danger"
        else
          "default"
        end
      end

      def check_expectations(hsh)
        # $stderr << hsh["expect"].inspect
        # $stderr << "\n" << hsh["result"].inspect << "\n"

        expect = hsh["expect"]
        return true unless expect
        result = hsh["result"]
        headers = result["headers"]

        pass = true
        if expect["code"]
          pass &&= expect["code"].to_s == result["code"].to_s
        end

        if expect["headers"]
          expect["headers"].each do |k,v|
            case v
            when String then pass &&= headers[k.downcase] == expect["headers"][k.downcase]
            when Hash
              maybe_eval = v["eval"]
              if maybe_eval
                pass &&= eval("headers=#{headers}; " + maybe_eval)
              end
            end
          end
        end

        if expect["eval"]
          pass &&= expect["test_result"]
          expect.delete("test_result")
        end

        if eb = expect["body"]
          case eb
          when String
            pass &&= result["body"].to_s[Regexp.new(eb.to_s)]
          when Array
            pass &&= result["body"].include?(eb)
          when Hash
            pass &&= result["body"] == eb
          end
        end

        pass
      end

      def render(body, type)
        result =
          case type
          when :json
            Disco::Formater.json_pp_html(body)
          when :xml
            h(body || "").gsub(/  /, "&nbsp;&nbsp;").gsub("\n", "<br/>")
          when :csv
            body.to_s.
              gsub("[[", "[<br/>&nbsp;&nbsp;[").
              gsub("], ", "],<br/>&nbsp;&nbsp;").
              gsub("]]", "]<br/>]")
          else
            h(body.to_s || "").gsub("\n", "<br/>")
          end
        if (type != :json) and (result.size > CF.max_body_length)
          result[0..MAX_BODY_LENGTH] + "<br/> ----- omitted: (#{result.size - CF.max_body_length} bytes) -----"
        else
          result
        end
      end

      def render_example(b)
        ex = b.get(:ex)

        return "" if ex.has_key?("skip")

        passed = check_expectations(ex)

        div class: "panel panel-#{passed ? 'success' : 'danger'} col-md-offset-1" do
          div class: "panel-heading", "data-toggle"=>"collapse",
              "data-target"=>"#panel_#{ex.hash}", "aria-expanded"=>"false"  do
            h4 class: "panel-title" do
              ex["description"] || "..no description.."
            end
          end
          div class: "panel-body collapse", id: "panel_#{ex.hash}" do
            h5 "REQUEST PATH: <span class='bordered'>#{ex['path_with_params']}</span>"

            h5 "REQUEST HEADERS"
            if Hash === ex["headers"]
              samp do
                table class: "table table-condensed table-bordered" do
                  ex["headers"].each do |k, v|
                    tr do
                      td(class: "text-right small text-muted", width: "30%") { D::Runner.normlize_header_key(k) }
                      td v
                    end
                  end
                end
              end
            end

            h5 "REQUEST PARAMS"
            if Hash === ex["params"]
              table class: "table table-condensed table-bordered" do
                tr do
                  th(class: "text-center", width: "30%") { "query parameter name" }
                  th(class: "text-center") { "value" }
                end
                ex["params"].each do |k,v|
                  tr do
                    td(class: "text-right small text-muted", width: "30%") { k }
                    td do
                      code(class: "lang-ruby") { v.to_s }
                    end
                  end
                end
              end
            else
              span { "no given params" }
            end

            if ["post", "put"].include? b.get(:meth)
              h5 "REQUEST BODY"
              code(class: "lang-ruby") { ex["body"].to_s }
            end

            h5 "CURL STRING"
            div class: "input-group" do
              span(class: "input-group-addon glyphicon glyphicon-share-alt")
              input(onClick: "this.select();", type: "text", class: "form-control", value: h(ex["curl"]))
            end

            hr

            h5 "EXPECTING:"
            div class: "alert alert-warning" do
              ex["expect"].inspect
            end

            hr

            h5 do
              span "RESPONSE  CODE: "
              span(class: "label label-#{response_code_to_color(ex['result']['code'])}") do
                "#{ex['result']['code']} #{ex['result']['message']}"
              end
            end

            samp do
              if Hash === ex["result"]
                table class: "table table-condensed table-bordered" do
                  ex["result"]["headers"].each do |k,v|
                    if CF.recipe["headers"] and Array === CF.recipe["headers"]["exclude"]
                      next if CF.recipe["headers"]["exclude"].include? k
                    end
                    tr do
                      td(class: "text-right small text-muted", width: "30%") { D::Runner.normlize_header_key(k)}
                      td v
                    end
                  end
                  tr do
                    td(class: "text-right small text-muted", width: "30%") { "BODY" }
                    td(class: "result lang-#{hl(ex['result']['type'])}") do
                      div(style: "width: 720px; overflow: scroll; white-space: nowrap;") do
                        render(ex["result"]["body"], ex["result"]["type"])
                      end
                    end
                  end
                end
              else
                h5 ex["result"].message
              end
            end
            h5 "REQUEST TAKE: <kbd>#{ex['result']['response_time']} sec</kbd>"
          end
        end
      end
    end

    def output_json
      File.open(fullname, "wb") do |o|
        o << json_pp(Configurator.recipe)
      end
    end

    def json_pp(obj, space="  ")
      JSON.pretty_generate(obj, {indent: space})
    end

    def json_pp_html(obj)
      json_pp(obj, "&nbsp;&nbsp").gsub("\n", "<br/>")
    end

    def fullname
      File.join(dirname, filename)
    end

    def filename
      File.basename(Configurator.options[:output])
    end

    def dirname
      File.dirname File.expand_path(Configurator.options[:output])
    end
  end

  VERSION = "0.0.1"

  module Configurator extend self
    attr_accessor :root, :options, :config, :recipe, :recipe_file

    def get_config!
      self.root = Dir.getwd

      self.options = {
        output: "doc/index.html",
      }

      OptionParser.new do |opts|
        opts.banner = "Usage: ruby disco.rb [api_recipe_file] [options]"

        opts.on("-v", "--version", "print version") do |v|
          puts "\nDisco version: #{Disco::VERSION}"
          exit(0)
        end

        opts.on("-h", "--help", "Prints this help") do
          puts opts
          exit(0)
        end

        opts.on("-oFILE", "--output=FILE", "Output to file. Output format detects from file extension (html, json)") do |file|
          self.options[:output] = file
        end

        opts.on("-lINTEGER", "--max-body-length=INTEGER", "Restrict response body displaying length (bytes, default=#{::MAX_BODY_LENGTH})") do |i|
          self.options[:max_body_length] = Integer(i)
        end

        opts.on("-g[FILE]", "--generate=[FILE]", "Generate recipe template. Output format detects from file extension (yml, json)") do |file|
          file ||= "api.yml"
          case File.extname(file)
          when ".yml", "yaml"
            File.open(file, "wb+") do |f|
              f << DATA.read << "\n"
            end
          when ".json"
            File.open(file, "wb+") do |f|
              f << JSON.pretty_generate(YAML.load(DATA.read), {indent: "  "})
            end
          else
            raise ArgumentError.new "Unknown recipe format: '#{file}' Please use yml or json formats only"
          end

          puts "\nRecipe template saved to: #{file}"
          exit(1)
        end

      end.parse!

      maybe_apiyaml = File.readable?(File.join(self.root, "spec/api.yml")) ? File.join(self.root, "spec/api.yml") : "api.yml"

      self.recipe_file = ARGV.first || ENV["RECIPE"] || maybe_apiyaml
      self.recipe = load_recipe(self.recipe_file)

    end

    def load_recipe(filename)
      if not File.stat(filename).readable_real?
        raise ArgumentError.new("Cannot read recipe file: #{filename}")
      end

      case type = File.extname(filename)
      when '.yaml', '.yml' then YAML.load(ERB.new(File.read(filename)).result)
      when '.json'         then JSON.parse(File.read(filename))
      else
        raise ArgumentError.new("unknown recipe type: #{type}")
      end
    end

    def max_body_length
      self.options[:max_body_length] || ::MAX_BODY_LENGTH
    end
  end

  CF = Configurator

  module Runner extend self
    def run
      CF.get_config!

      load_require()

      run_before_suit()
      puts "-- Starting test suit\n"
      request_loop()
      puts "\nsaving output"
      Formater.format_and_save_output()
      run_after_suit()
    end

    def request_loop
      request = Request.new(base_url: recipe["base_url"],
                            port:     recipe["port"])

      recipe["only_exclusive_examples"] = detect_if_only_examples(recipe["endpoints"])

      recipe["endpoints"].each do |path, endpoint|
        request_path = normalize_path(path)
        endpoint["path"] = request_path
        endpoint["methods"].each do |meth, request_examples|
          request_examples.each do |example|
            if recipe["only_exclusive_examples"]
              next if not example.has_key?("only")
            else
              next if example.has_key?("skip")
            end
            example["headers"] ||= {}

            run_code(recipe["run"]["before_each"]) if recipe["run"] && recipe["run"]["before_each"]
            run_code(example["before"]) if example["before"]
            example["path"] = build_path(example, request_path)

            opts = {
              method:  meth,
              path:    example["path"],
              headers: example["headers"],
              params:  example["params"],
              payload: encode_body(example["body"])
            }

            result =
              begin
                request.do_request(opts).tap{ print "." }
              rescue => e
                print "!"
                e
              end
            example["result"] = result
            example["curl"]   = generate_curl(binding)

            if example["expect"] && example["expect"]["eval"]
              example["expect"]["test_result"] = eval(example["expect"]["eval"],binding, CF.recipe_file)
            end

            run_code(example["after"]) if example["after"]
            run_code(recipe["run"]["after_each"]) if recipe["run"] && recipe["run"]["after_each"]
          end
        end

      end
    end

    def detect_if_only_examples(ex)
      !! ex.to_s[/"only"=>/]
    end


    def build_path(ex, path)
      case ex["path"]
      when String then File.join(path, ex["path"])
      when Hash then File.join(path, eval(ex["path"]["eval"]))
      else
        path
      end
    end

    def encode_body(b)
      case b
      when String then b
      when Hash
        case
        when b["json"] then JSON.dump(b["json"])
        end
      end
    end

    def generate_curl(b)
      ex = b.get(:example)

      headers = ex["headers"] .map do |k,v|
        "-H \"#{normlize_header_key(k)}: #{v}\""
      end.join(" ")

      meth = b.get(:meth).upcase

      %{curl -i -X #{meth} #{headers} "#{real_url(b)}"}
    end

    def real_url(b)
      r  = recipe()
      ex = b.get(:example)

      path =
        if r['original'] && r['original']['base_url']
          r['original']['base_url'] +
            if r['original']['port']
              ":" + (r['original']['port']).to_s
            else
              ""
            end
        else
          r['base_url'] + ":" + r['port'].to_s
        end

      params = ex["params"]
      params = URI.encode_www_form(params) if Hash === params

      real_url =
        if params
          ex['path_with_params'] = "#{ex['path']}?#{params}"
          File.join(path, ex['path']) + "?#{params}"
        else
          ex['path_with_params'] = ex['path']
          File.join(path, ex['path'])
        end

      ex["full_url"] = real_url
    end

    def load_require
      if code_to_preload = recipe["require"]
        puts "Trying to load #{code_to_preload}"
        require code_to_preload
      end
    end

    def run_before_suit
      return unless recipe["run"] and String === (r = recipe["run"]["before_all"])
      run_code(r)
    end

    def run_after_suit
      return unless recipe["run"] and String === (r = recipe["run"]["after_all"])
      run_code(r)
    end

    def run_code(code)
      if maybe_shell_code?(code)
        result = system(code[1..-1])
        if not result
          case recipe["run"]["on_error"]
          when "exit"  then puts "\nExecuting script '#{code[1..-1]}' failed! #{$?}"; exit(1)
          when "alert" then puts "\nExecuting script '#{code[1..-1]}' failed! #{$?}"
          when "skip"  then return
          else
          end
        end
      else
        eval(code)
      end
    end

    def maybe_shell_code?(str)
      !! str[/\A\\/]
    end

    def recipe
      CF.recipe || {}
    end

    def normlize_header_key(key)
      key.split('-').map(&:capitalize).join('-')
    end

    def normalize_path(path)
      if path.start_with?("http://")
        return path
      end
      if String === recipe["version_api"]
        return File.join("/", recipe["version_api"], path)
      end
      File.join("/", path)
    end

  end
end

D = Disco


require 'pry'
require 'byebug'

begin
  Disco::Runner::run
rescue => e
  raise
  puts "Error! #{e.message}"
  exit(1)
end


#Pry.start


__END__
# service URL and port to be accessed
base_url: http://localhost
port: 4567
# Version string to be added into each request "http://example.com/{version_api}/endpoint"
version_api: v1

title: Your API
subtitle: something helpful about your api
description: "Very long and
  multiline string"
footer: (c) Your name
original:
  # what will be printed into  formatted output, your "real" API URL
  base_url: http://example.com
  port:

# require arbitrary ruby file before starting tests
require:
# in case if you has preloaded ruby file, here you can
# call any ruby methods, say: Namespace::DB.clean() or smth
# also you could run any shell scripts: '\my_script.sh -v clear_db' starting from backslash
run:
  before_all:
  after_all:
  before_each:
  after_each:
  on_error: exit # exit, alert, skip
headers:
  # exclude headers from resulting documentation
  exclude: [x-webmachine-trace-id]

# where you define API endpoints
endpoints:
  # /{version_api}/ping
  ping:
    description: Base point for requesting stats
    params: Not expecting any parameters
    methods:
      get:
        # array of request examples
        -
        # skip: true # in case if you want temporary skip this example
        # only: true # in case if you want see only this (and other examples with key only: set)
        # path: # String if you want custom path
        # path:
        #   eval:
          description: Describe this example
          headers:
            accept: application/json
          params:
            one: 22
            duo: Expecting the World!
            trua: 20-03-2016
          expect:
            code: 200
            content-type: application/json;charset=utf-8
          before:
          after:
        -
          description: Describe this example
          headers:
            accept: text/plain
          expect:
            code: 200
            content-type: text/plain
          before:
          after:
