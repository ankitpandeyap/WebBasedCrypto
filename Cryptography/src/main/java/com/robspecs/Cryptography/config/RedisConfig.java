package com.robspecs.Cryptography.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.task.TaskExecutor;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.listener.PatternTopic;
import org.springframework.data.redis.listener.RedisMessageListenerContainer;
import org.springframework.data.redis.listener.adapter.MessageListenerAdapter;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import com.robspecs.Cryptography.serviceImpl.RedisSubscriberImpl;

import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;


@Configuration
public class RedisConfig {

	private static final Logger logger = LoggerFactory.getLogger(RedisConfig.class);

	@Bean
	public RedisConnectionFactory redisConnectionFactory() {
		LettuceConnectionFactory lettuceConnectionFactory = new LettuceConnectionFactory();
		logger.debug("RedisConnectionFactory bean created using Lettuce: {}", lettuceConnectionFactory);
		return lettuceConnectionFactory; // default localhost:6379// will use password
	}

	/*
	 * // Inject properties from application.properties/yml
	 * 
	 * @Value("${spring.data.redis.host:localhost}") // Default to localhost if not
	 * specified private String redisHost;
	 * 
	 * @Value("${spring.data.redis.port:6379}") // Default to 6379 if not specified
	 * private int redisPort;
	 * 
	 * @Value("${spring.data.redis.password:}") // Default to empty string (no
	 * password) if not specified private String redisPassword;
	 * 
	 * @Bean public RedisConnectionFactory redisConnectionFactory() { logger.
	 * info("Configuring RedisConnectionFactory with host: {}, port: {}, password provided: {}"
	 * , redisHost, redisPort, !redisPassword.isEmpty()); // Log configuration
	 * details
	 * 
	 * // Use RedisStandaloneConfiguration to set host, port, and password
	 * RedisStandaloneConfiguration redisStandaloneConfiguration = new
	 * RedisStandaloneConfiguration();
	 * redisStandaloneConfiguration.setHostName(redisHost);
	 * redisStandaloneConfiguration.setPort(redisPort);
	 * 
	 * if (!redisPassword.isEmpty()) {
	 * redisStandaloneConfiguration.setPassword(redisPassword);
	 * logger.debug("Redis password set for connection factory."); } else {
	 * logger.debug("No Redis password configured."); }
	 * 
	 * LettuceConnectionFactory lettuceConnectionFactory = new
	 * LettuceConnectionFactory(redisStandaloneConfiguration); // It's good practice
	 * to call afterPropertiesSet() if not managed by Spring's full lifecycle //
	 * lettuceConnectionFactory.afterPropertiesSet(); // Usually not needed if
	 * Spring manages the bean lifecycle
	 * logger.debug("LettuceConnectionFactory bean created for Redis at {}:{}",
	 * redisHost, redisPort); return lettuceConnectionFactory; }*
	 * 
	 */

	@Bean
	public RedisTemplate<String, String> redisTemplate(RedisConnectionFactory connectionFactory) {
		RedisTemplate<String, String> template = new RedisTemplate<>();
		template.setConnectionFactory(connectionFactory);
		template.setKeySerializer(new StringRedisSerializer());
		template.setValueSerializer(new StringRedisSerializer());
		logger.debug("RedisTemplate bean created");
		return template;
	}

	@Bean
	public RedisMessageListenerContainer redisContainer(RedisConnectionFactory cf,
			MessageListenerAdapter listenerAdapter, TaskExecutor redisMessageExecutor) {
		logger.info("Configuring RedisMessageListenerContainer.");
		RedisMessageListenerContainer container = new RedisMessageListenerContainer();
		container.setConnectionFactory(cf);
		logger.debug("RedisMessageListenerContainer set connection factory.");

		// Add the listener adapter to listen on the "inbox.*" pattern topic
		container.addMessageListener(listenerAdapter, new PatternTopic("inbox.*"));
		container.setTaskExecutor(redisMessageExecutor);
		logger.info("RedisMessageListenerContainer added listener for topic 'inbox.*'.");

		// Important: The container needs to be started for listeners to become active.
		// Spring usually handles this automatically if the bean is properly managed,
		// but for explicit control or debugging, you might manually start/stop it.
		// container.afterPropertiesSet(); // Not strictly necessary if Spring manages
		// lifecycle
		// container.start(); // Not strictly necessary if Spring manages lifecycle

		logger.debug("RedisMessageListenerContainer bean created.");
		return container;
	}

	@Bean
	public MessageListenerAdapter listenerAdapter(RedisSubscriberImpl subscriber) {
		logger.info("Configuring MessageListenerAdapter for RedisSubscriber.");
		// The 'onMessage' method in RedisSubscriber will be invoked when a message
		// arrives
		MessageListenerAdapter adapter = new MessageListenerAdapter(subscriber, "onMessage");
		logger.debug("MessageListenerAdapter bean created, delegating to 'onMessage' method of RedisSubscriber.");
		return adapter;
	}

	@Bean(name = "redisMessageExecutor") // Explicitly named for clarity
	public TaskExecutor redisMessageExecutor() {
		logger.info("Configuring dedicated TaskExecutor 'redisMessageExecutor' for Redis message listeners.");
		ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
		executor.setCorePoolSize(5); // Adjust as needed based on expected message volume and processing time
		executor.setMaxPoolSize(10); // Adjust as needed
		executor.setQueueCapacity(25); // Adjust as needed
		executor.setThreadNamePrefix("redis-listener-"); // Clear prefix for debugging
		executor.initialize();
		logger.debug(
				"TaskExecutor 'redisMessageExecutor' initialized with corePoolSize={}, maxPoolSize={}, queueCapacity={}",
				executor.getCorePoolSize(), executor.getMaxPoolSize(), executor.getQueueCapacity());
		return executor;
	}

	@Bean(name = "redisJsonTemplate") // Give it a distinct name to avoid ambiguity
	public RedisTemplate<String, Object> redisJsonTemplate(RedisConnectionFactory connectionFactory) {
		RedisTemplate<String, Object> template = new RedisTemplate<>();
		template.setConnectionFactory(connectionFactory);
		template.setKeySerializer(new StringRedisSerializer()); // Keys are still strings
		template.setHashKeySerializer(new StringRedisSerializer()); // If you use hash operations

		// Use GenericJackson2JsonRedisSerializer for serializing/deserializing Objects
		// to/from JSON
		template.setValueSerializer(new GenericJackson2JsonRedisSerializer());
		template.setHashValueSerializer(new GenericJackson2JsonRedisSerializer()); // If you use hash operations

		template.afterPropertiesSet(); // Ensure serializers are set up before use
		logger.debug("RedisTemplate<String, Object> 'redisJsonTemplate' bean created with JSON serializer.");
		return template;

	}
}
