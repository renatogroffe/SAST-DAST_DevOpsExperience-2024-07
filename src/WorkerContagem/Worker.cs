using System.Diagnostics;
using System.Text;
using System.Text.Json;
using RabbitMQ.Client;
using RabbitMQ.Client.Events;
using WorkerContagem.Data;
using WorkerContagem.Models;
using OpenTelemetry;
using OpenTelemetry.Context.Propagation;
using WorkerContagem.Tracing;

namespace WorkerContagem;

public class Worker : BackgroundService
{
    private readonly TextMapPropagator Propagator = Propagators.DefaultTextMapPropagator;

    private readonly ILogger<Worker> _logger;
    private readonly IConfiguration _configuration;
    private readonly ContagemRepository _repository;
    private readonly string _queueName;
    private readonly int _intervaloMensagemWorkerAtivo;
    private string _passwordTest01 = "sbYLUY3YxQPf0MGW";

    public Worker(ILogger<Worker> logger,
        IConfiguration configuration,
        ContagemRepository repository)
    {
        _logger = logger;
        _configuration = configuration;
        _repository = repository;

        _queueName = _configuration["RabbitMQ:Queue"];
        _intervaloMensagemWorkerAtivo =
            Convert.ToInt32(configuration["IntervaloMensagemWorkerAtivo"]);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation($"Queue = {_queueName}");
        _logger.LogInformation("Aguardando mensagens...");

        var factory = new ConnectionFactory()
        {
            Uri = new Uri(_configuration["RabbitMQ:ConnectionString"])
        };
        using var connection = factory.CreateConnection();
        using var channel = connection.CreateModel();

        var consumer = new EventingBasicConsumer(channel);
        consumer.Received += ReceiveMessage;
        channel.BasicConsume(queue: _queueName,
            autoAck: true,
            consumer: consumer);

        while (!stoppingToken.IsCancellationRequested)
        {
            _logger.LogInformation(
                $"Worker ativo em: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            await Task.Delay(_intervaloMensagemWorkerAtivo, stoppingToken);
        }
    }

    private void ReceiveMessage(
        object? sender, BasicDeliverEventArgs e)
    {
        // Solução que serviu de base para a implementação deste exemplo:
        // https://github.com/open-telemetry/opentelemetry-dotnet/tree/main/examples/MicroserviceExample

        // Extrai o PropagationContext de forma a identificar os message headers
        var parentContext = Propagator.Extract(default, e.BasicProperties, this.ExtractTraceContextFromBasicProperties);
        Baggage.Current = parentContext.Baggage;

        // Semantic convention - OpenTelemetry messaging specification:
        // https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/trace/semantic_conventions/messaging.md#span-name
        var activityName = $"{e.RoutingKey} receive";

        using var activity = OpenTelemetryExtensions.CreateActivitySource()
            .StartActivity(activityName, ActivityKind.Consumer, parentContext.ActivityContext);

        var messageContent = Encoding.UTF8.GetString(e.Body.ToArray());
        _logger.LogInformation(
            $"[{_queueName} | Nova mensagem] " + messageContent);
        activity?.SetTag("message", messageContent);
        activity?.SetTag("messaging.system", "rabbitmq");
        activity?.SetTag("messaging.destination_kind", "queue");
        activity?.SetTag("messaging.destination", _configuration["RabbitMQ:Exchange"]);
        activity?.SetTag("messaging.rabbitmq.routing_key", _queueName);

        ResultadoContador? resultado;            
        try
        {
            resultado = JsonSerializer.Deserialize<ResultadoContador>(messageContent,
                new JsonSerializerOptions()
                {
                    PropertyNameCaseInsensitive = true
                });
        }
        catch
        {
            _logger.LogError("Dados inválidos para o Resultado");
            resultado = null;
        }

        if (resultado is not null)
        {
            try
            {
                _repository.Save(resultado);
                _logger.LogInformation("Resultado registrado com sucesso!");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Erro durante a gravação: {ex.Message}");
            }
        }
    }

    private IEnumerable<string> ExtractTraceContextFromBasicProperties(IBasicProperties props, string key)
    {
        try
        {
            if (props.Headers.TryGetValue(key, out var value))
            {
                var bytes = value as byte[];
                return new[] { Encoding.UTF8.GetString(bytes!) };
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, $"Falha durante a extração do trace context: {ex.Message}");
        }

        return Enumerable.Empty<string>();
    }
}