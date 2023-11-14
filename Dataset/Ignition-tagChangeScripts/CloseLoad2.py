def valueChanged(tag, tagPath, previousValue, currentValue, initialChange, missedEvents):
		current_value = currentValue.value
							
		if current_value == True:
			system.tag.write('[default]C2', 0)
			system.tag.write('[default]R2', 0)
			system.tag.write('[default]CloseLoad2', False)
			system.tag.write('[default]DecLoad2', False)
			system.tag.write('[default]IncLoad2', False)